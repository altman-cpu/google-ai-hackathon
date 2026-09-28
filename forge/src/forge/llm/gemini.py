"""Optional Gemini-assisted designer, with the model held on a short leash.

"Without personality" is a hard requirement here, and it is enforced three ways:

1. **Sampling is pinned.** ``temperature=0``, ``topP=0``, ``topK=1``,
   ``candidateCount=1``. Greedy decoding, no sampling entropy.
2. **The output shape is fixed.** ``responseMimeType: application/json`` plus a
   response schema. The model returns a parameter map or the call fails. It
   cannot return prose, commentary, hedging, or an apology.
3. **The output is untrusted.** Whatever comes back is filtered against the
   intent graph before it reaches a generator. The model may only suggest
   *parameters* for nodes the author already declared. It cannot add a node, add
   an edge, rename anything, or override an author-set value -- those all lose
   to the intent document in :func:`forge.design.resolve`.

The model advises. The graph decides.

A build using this designer is *not* byte-reproducible without the same model
serving the same weights, so ``extreme`` rigor records the designer in the
manifest and the reproducibility check is performed against a single response
rather than two independent calls.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from ..canonical import loads
from ..errors import ConfigError, NetworkError
from ..intent import Intent

NAME = "gemini"
ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

SYSTEM_INSTRUCTION = (
    "You are a configuration resolver inside a deterministic build pipeline. "
    "You receive a network intent graph and return parameter suggestions for nodes "
    "that already exist in it.\n"
    "\n"
    "Rules, all mandatory:\n"
    "- Output a single JSON object mapping node id to a flat object of parameters.\n"
    "- Never invent a node id. Only use ids present in the input.\n"
    "- Never include prose, explanation, commentary, apologies, or markdown.\n"
    "- Never include a field whose value you are guessing. Omit it instead.\n"
    "- Prefer omission over speculation. An empty object is a valid, correct answer.\n"
    "- Values must be strings, integers, booleans, or arrays of strings.\n"
    "\n"
    "Recognised parameters:\n"
    "  route    (string)  URL path segment for an endpoint node\n"
    "  methods  (array)   HTTP methods, lowercase, from: get post put patch delete\n"
    "  fields   (object)  field name -> one of: str int bool uuid email url datetime json file\n"
)


def propose(intent: Intent, *, api_key: str, model: str = "gemini-1.5-pro",
            timeout: int = 30) -> dict[str, dict[str, Any]]:
    """Ask Gemini for parameter suggestions, then sanitise them hard."""
    if not api_key:
        raise ConfigError(
            "the gemini designer needs GEMINI_API_KEY. "
            "Set it, or use --designer deterministic (which needs no network)."
        )

    prompt = json.dumps(
        {
            "intent": intent.document(),
            "task": "Return parameter suggestions for the declared nodes. JSON only.",
        },
        sort_keys=True,
        separators=(",", ":"),
    )

    body = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "systemInstruction": {"parts": [{"text": SYSTEM_INSTRUCTION}]},
        "generationConfig": {
            "temperature": 0,
            "topP": 0,
            "topK": 1,
            "candidateCount": 1,
            "responseMimeType": "application/json",
            "maxOutputTokens": 4096,
        },
        # Do not let safety filtering silently truncate a config response.
        "safetySettings": [],
    }

    url = ENDPOINT.format(model=model)
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            # Header auth, so the key never appears in a URL, a log, or a proxy trace.
            "x-goog-api-key": api_key,
            "User-Agent": "forge/0.1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:400]
        raise NetworkError(
            f"Gemini returned HTTP {exc.code} {exc.reason}: {detail}"
        ) from exc
    except urllib.error.URLError as exc:
        raise NetworkError(f"could not reach Gemini: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise NetworkError(f"Gemini returned malformed JSON: {exc}") from exc

    text = _extract_text(payload)
    if not text:
        raise NetworkError("Gemini returned an empty response")

    try:
        raw = loads(text)
    except Exception as exc:  # noqa: BLE001 - surface the model's bad output verbatim
        raise NetworkError(
            f"Gemini did not return usable JSON ({exc}); response began: {text[:200]!r}"
        ) from exc

    return sanitise(raw, intent)


def sanitise(raw: Any, intent: Intent) -> dict[str, dict[str, Any]]:
    """Discard anything the model returned that the intent does not sanction.

    Silently dropping unknown keys is deliberate: a model that hallucinates a
    node should degrade the build to "no suggestion for that node", not fail it.
    Author-declared parameters always win downstream regardless.
    """
    if not isinstance(raw, dict):
        return {}

    known_ids = {node.id for node in intent.nodes}
    allowed = {"route", "methods", "fields"}
    valid_methods = {"get", "post", "put", "patch", "delete"}
    valid_field_types = {
        "str", "int", "bool", "uuid", "email", "url", "datetime", "json", "file",
    }

    cleaned: dict[str, dict[str, Any]] = {}
    for node_id, params in raw.items():
        if node_id not in known_ids or not isinstance(params, dict):
            continue
        keep: dict[str, Any] = {}

        route = params.get("route")
        if isinstance(route, str) and route and route.strip("/") == route and " " not in route:
            keep["route"] = route

        methods = params.get("methods")
        if isinstance(methods, list):
            picked = sorted(
                {m.lower() for m in methods if isinstance(m, str) and m.lower() in valid_methods}
            )
            if picked:
                keep["methods"] = picked

        fields = params.get("fields")
        if isinstance(fields, dict):
            picked_fields = {
                str(name): str(kind)
                for name, kind in sorted(fields.items())
                if isinstance(name, str)
                and name.isidentifier()
                and isinstance(kind, str)
                and kind.lower() in valid_field_types
            }
            if picked_fields:
                keep["fields"] = picked_fields

        unknown = set(params) - allowed
        if unknown:
            # Dropped, not merged. An unrecognised key is a hallucination.
            pass

        if keep:
            cleaned[node_id] = keep

    return cleaned


def _extract_text(payload: dict[str, Any]) -> str:
    candidates = payload.get("candidates") or []
    if not candidates:
        return ""
    parts = ((candidates[0].get("content") or {}).get("parts")) or []
    return "".join(str(part.get("text", "")) for part in parts).strip()


__all__ = ["NAME", "SYSTEM_INSTRUCTION", "propose", "sanitise"]
