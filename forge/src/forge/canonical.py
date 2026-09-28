"""Canonical serialisation.

Digests are only meaningful if the bytes being hashed are reproducible. This
module defines the single canonical encoding used everywhere in forge, a strict
subset of RFC 8785 (JSON Canonicalisation Scheme):

* object keys sorted by UTF-16 code unit, as ``sorted()`` does for BMP strings
* no insignificant whitespace
* UTF-8 output, no ``\\uXXXX`` escaping beyond what JSON mandates
* integers emitted without a decimal point
* floats rejected outright -- binary floats are not reproducible across
  languages, and forge has no need for them (all money is integer ``usei``)
* ``NaN`` / ``Infinity`` rejected
* only ``dict``, ``list``, ``str``, ``int``, ``bool``, ``None`` permitted

Rejecting floats rather than rounding them is intentional: a silent rounding
rule is a silent consensus bug waiting to happen.
"""

from __future__ import annotations

import json
from typing import Any

from .errors import IntegrityError

# Types that may appear in a canonicalisable document.
_ATOMS = (str, bool, type(None))


def _check(value: Any, path: str = "$") -> None:
    """Recursively reject anything that cannot be canonically encoded."""
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        raise IntegrityError(
            f"float at {path}: floats are not canonically encodable; "
            "use an integer (money is integer usei) or a decimal string"
        )
    if isinstance(value, dict):
        for key, sub in value.items():
            if not isinstance(key, str):
                raise IntegrityError(f"non-string object key at {path}: {key!r}")
            _check(sub, f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, sub in enumerate(value):
            _check(sub, f"{path}[{index}]")
        return
    raise IntegrityError(f"value of type {type(value).__name__} at {path} is not canonicalisable")


def _normalise(value: Any) -> Any:
    """Convert tuples to lists so json.dumps emits arrays deterministically."""
    if isinstance(value, dict):
        return {key: _normalise(sub) for key, sub in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalise(sub) for sub in value]
    return value


def canonical_json(value: Any) -> str:
    """Return the canonical JSON text for ``value``."""
    _check(value)
    return json.dumps(
        _normalise(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_bytes(value: Any) -> bytes:
    """Return the canonical UTF-8 bytes for ``value``.

    This is the *only* function that should ever feed a hash function.
    """
    return canonical_json(value).encode("utf-8")


def loads(text: str | bytes) -> Any:
    """Parse JSON, rejecting anything that is not canonicalisable.

    Used on every untrusted input boundary (files, HTTP bodies) so malformed
    documents fail at the edge rather than deep inside a generator.
    """
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise IntegrityError(f"input is not valid UTF-8: {exc}") from exc
    try:
        value = json.loads(text, parse_float=_reject_float)
    except json.JSONDecodeError as exc:
        raise IntegrityError(f"invalid JSON: {exc}") from exc
    _check(value)
    return value


def _reject_float(raw: str) -> Any:
    raise IntegrityError(
        f"float literal {raw!r} in input: forge documents must not contain floats"
    )


__all__ = ["canonical_json", "canonical_bytes", "loads"]
