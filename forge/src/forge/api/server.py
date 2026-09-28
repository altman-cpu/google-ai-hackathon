"""REST API, on the standard library only.

No framework, because the whole package has no third-party dependencies and
this endpoint surface is small enough that a framework would be the larger
half of it.

Routes::

    GET  /healthz                     liveness
    GET  /v1/catalog                  the published SEI price list
    GET  /v1/networks                 known SEI networks and which is mainnet
    GET  /v1/generators               registered generators
    POST /v1/validate                 validate an intent document
    POST /v1/design                   intent -> ordered build plan
    POST /v1/quote                    intent -> price and payment request
    POST /v1/build                    intent -> artifacts, manifest, signature
    POST /v1/verify-payment           check a payment request against the chain
    GET  /v1/objects                  iceberg surface (tips only)
    GET  /v1/objects/{digest}         one tip
    GET  /v1/objects/{digest}/body    one whole body

Responses are canonical JSON. ``/v1/build`` returns artifact *content* only when
the request sets ``"include_content": true``; otherwise it returns tips, which
is the iceberg rule applied to the wire: shape by default, mass on request.

This server is deliberately unauthenticated and is intended to run behind a
reverse proxy or on a trusted network. It never exposes a private key because
there is none to expose, but it will happily generate code for anyone who can
reach it.
"""

from __future__ import annotations

import base64
import json
import re
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from .. import __version__, generators, pipeline
from ..canonical import canonical_bytes, loads
from ..config import NETWORKS, Config
from ..errors import ForgeError
from ..iceberg import Iceberg
from ..payments import catalog as catalog_mod
from ..payments import gateway

MAX_BODY_BYTES = 1 << 20  # 1 MiB; intent documents are small
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class ForgeHandler(BaseHTTPRequestHandler):
    """Request handler. One instance per request, per the http.server contract."""

    server_version = f"forge/{__version__}"
    protocol_version = "HTTP/1.1"
    config: Config  # injected by serve()

    # ---- plumbing --------------------------------------------------------

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"  {self.address_string()} {fmt % args}", flush=True)

    def _send(self, status: int, payload: Any, *, raw: bytes | None = None,
              content_type: str = "application/json") -> None:
        body = raw if raw is not None else canonical_bytes(payload) + b"\n"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # This API is read-mostly and returns no credentials, but lock down the
        # obvious footguns anyway.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, message: str, kind: str = "error") -> None:
        self._send(status, {"error": {"kind": kind, "message": message}, "ok": False})

    def _read_json(self) -> Any:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            raise ForgeError("request body is empty")
        if length > MAX_BODY_BYTES:
            raise ForgeError(f"request body is {length} bytes, limit is {MAX_BODY_BYTES}")
        return loads(self.rfile.read(length))

    # ---- routing ---------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - http.server naming
        self._dispatch(self._get_routes())

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch(self._post_routes())

    def _dispatch(self, routes: dict[str, Callable[..., None]]) -> None:
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        try:
            handler = routes.get(path)
            if handler is not None:
                handler()
                return

            # Parameterised object routes.
            match = re.match(r"^/v1/objects/([0-9a-fA-F]+)(/body)?$", path)
            if match and self.command == "GET":
                self._object(match.group(1), body=bool(match.group(2)))
                return

            self._error(404, f"no route for {self.command} {path}", "not_found")
        except ForgeError as exc:
            self._error(400, str(exc), type(exc).__name__)
        except Exception as exc:  # noqa: BLE001
            traceback.print_exc()
            self._error(500, f"{type(exc).__name__}: {exc}", "internal")

    def _get_routes(self) -> dict[str, Callable[..., None]]:
        return {
            "/": self._index,
            "/healthz": self._healthz,
            "/v1/catalog": self._catalog,
            "/v1/networks": self._networks,
            "/v1/generators": self._generators,
            "/v1/objects": self._surface,
        }

    def _post_routes(self) -> dict[str, Callable[..., None]]:
        return {
            "/v1/validate": self._validate,
            "/v1/design": self._design,
            "/v1/quote": self._quote,
            "/v1/build": self._build,
            "/v1/verify-payment": self._verify_payment,
        }

    # ---- handlers --------------------------------------------------------

    def _index(self) -> None:
        self._send(200, {
            "schema": "forge.api/v1",
            "custody": "none: forge never holds a private key",
            "network": self.config.network.name,
            "routes": sorted(self._get_routes()) + sorted(self._post_routes()),
            "service": "forge",
            "version": __version__,
        })

    def _healthz(self) -> None:
        self._send(200, {"ok": True, "version": __version__})

    def _catalog(self) -> None:
        self._send(200, catalog_mod.published_catalog())

    def _networks(self) -> None:
        self._send(200, {
            "schema": "forge.networks/v1",
            "active": self.config.network.name,
            "mainnet_opt_in": self.config.allow_mainnet,
            "networks": [
                {
                    "chain_id": network.chain_id,
                    "evm_chain_id": network.evm_chain_id,
                    "is_mainnet": network.is_mainnet,
                    "name": name,
                }
                for name, network in sorted(NETWORKS.items())
            ],
        })

    def _generators(self) -> None:
        self._send(200, {"generators": generators.available()})

    def _validate(self) -> None:
        document = self._intent_payload(self._read_json())
        intent, warnings = pipeline.load_intent(document)
        rigor = pipeline.effective_rigor(intent, self.config)
        self._send(200, {
            "digest": intent.digest_hex,
            "edges": len(intent.edges),
            "name": intent.name,
            "nodes": len(intent.nodes),
            "ok": True,
            "rigor": rigor.value,
            "warnings": warnings,
        })

    def _design(self) -> None:
        payload = self._read_json()
        document = self._intent_payload(payload)
        intent, warnings = pipeline.load_intent(document)
        plan = pipeline.design(
            intent, self.config, designer=str(payload.get("designer", "deterministic"))
        )
        self._send(200, {"ok": True, "plan": plan.document(), "warnings": warnings})

    def _quote(self) -> None:
        payload = self._read_json()
        result = pipeline.build(
            self._intent_payload(payload),
            self.config,
            designer=str(payload.get("designer", "deterministic")),
            sign=False,
            payee=payload.get("payee"),
            write=False,
            store=False,
        )
        self._send(200, {
            "ok": True,
            "payment_request": result.payment.document() if result.payment else None,
            "quote": result.quote.document(),
        })

    def _build(self) -> None:
        payload = self._read_json()
        include_content = bool(payload.get("include_content", False))
        result = pipeline.build(
            self._intent_payload(payload),
            self.config,
            designer=str(payload.get("designer", "deterministic")),
            sign=payload.get("sign"),
            payee=payload.get("payee"),
            tx_hash=payload.get("tx"),
            write=False,
            store=bool(payload.get("store", True)),
        )

        body: dict[str, Any] = {
            "ok": True,
            "manifest": result.manifest.document(),
            "signature": result.signed.signature_armored,
            "summary": result.summary(),
        }
        if include_content:
            # base64 so arbitrary bytes survive JSON intact.
            body["artifacts"] = [
                {
                    "content_base64": base64.b64encode(artifact.content).decode("ascii"),
                    "digest": artifact.digest_hex,
                    "path": artifact.path,
                }
                for artifact in result.artifacts
            ]
        else:
            body["artifacts"] = [artifact.tip() for artifact in result.artifacts]
        self._send(200, body)

    def _verify_payment(self) -> None:
        payload = self._read_json()
        request_doc = payload.get("request")
        tx_hash = payload.get("tx")
        if not isinstance(request_doc, dict) or not tx_hash:
            raise ForgeError("body must contain 'request' (a payment request) and 'tx'")
        request = gateway.request_from_document(request_doc)
        settlement = gateway.verify_payment(self.config, request, str(tx_hash))
        self._send(200 if settlement.settled else 402, {
            "ok": settlement.settled,
            "settlement": settlement.document(),
        })

    def _surface(self) -> None:
        self._send(200, Iceberg(self.config.iceberg_dir).surface())

    def _object(self, digest: str, *, body: bool) -> None:
        key = digest.lower()
        if not _DIGEST_RE.match(key):
            self._error(
                400,
                "object keys are full 64-character hex digests; this store does not "
                "accept truncated or prefix keys",
                "bad_key",
            )
            return
        iceberg = Iceberg(self.config.iceberg_dir)
        if not iceberg.has(key):
            self._error(404, f"no object {key[:16]}...", "not_found")
            return
        tip = iceberg.tip(key)
        if body:
            self._send(200, None, raw=iceberg.body(key), content_type=tip.media_type)
        else:
            self._send(200, tip.document())

    @staticmethod
    def _intent_payload(payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ForgeError("request body must be a JSON object")
        document = payload.get("intent", payload)
        if not isinstance(document, dict):
            raise ForgeError("'intent' must be an object")
        return document


def serve(config: Config, *, host: str = "0.0.0.0", port: int = 8787) -> None:
    """Run the API until interrupted."""
    handler = type("BoundForgeHandler", (ForgeHandler,), {"config": config})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True

    banner = [
        f"forge {__version__} API",
        f"  listening   http://{host}:{port}",
        f"  network     {config.network.name}"
        + ("  *** MAINNET ***" if config.network.is_mainnet else "  (testnet)"),
        f"  rigor       {config.rigor.value}",
        f"  workdir     {config.workdir}",
        f"  payee       {config.payee or 'not set'}",
        "  custody     none -- forge holds no private keys",
        "",
        "  GET  /v1/catalog     what can be paid for, in SEI",
        "  POST /v1/build       intent -> signed, priced artifacts",
        "",
    ]
    print("\n".join(banner), flush=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down", flush=True)
    finally:
        server.server_close()


__all__ = ["ForgeHandler", "serve"]
