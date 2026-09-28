"""Bitcoin-style hashing primitives.

forge commits to artifacts the way Bitcoin commits to transactions:

* ``hash256`` -- SHA-256 applied twice (Bitcoin's ``HASH256``)
* a merkle tree over leaf digests, with Bitcoin's "duplicate the last node on
  an odd level" rule
* digests displayed in reversed byte order, matching how Bitcoin renders txids
  and block hashes in RPC output and block explorers

Why double SHA-256? It is what Bitcoin actually does, it costs nothing extra,
and it sidesteps length-extension on the outer hash. Where a plain single
SHA-256 is wanted (for example to interoperate with ``sha256sum``) use
``sha256`` explicitly -- the two are never mixed.

A note on CVE-2012-2459: Bitcoin's odd-node duplication rule means two distinct
leaf lists can produce the same merkle root (``[a, b, c]`` and
``[a, b, c, c]``). forge's default ``strict=True`` mode rejects duplicate leaves
outright, which removes the ambiguity. Set ``strict=False`` only when
reproducing a root computed by Bitcoin itself.
"""

from __future__ import annotations

import hashlib
from typing import Iterable, Sequence

from .errors import IntegrityError

DIGEST_SIZE = 32
ZERO_DIGEST = b"\x00" * DIGEST_SIZE


def sha256(data: bytes) -> bytes:
    """Single SHA-256. Use only where interop with ``sha256sum`` is required."""
    return hashlib.sha256(data).digest()


def hash256(data: bytes) -> bytes:
    """Bitcoin's HASH256: ``SHA256(SHA256(data))``."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hex_be(digest: bytes) -> str:
    """Render a digest in Bitcoin display order (reversed, big-endian hex)."""
    _require_digest(digest)
    return digest[::-1].hex()


def from_hex_be(text: str) -> bytes:
    """Parse a Bitcoin-display-order hex digest back to internal byte order."""
    raw = bytes.fromhex(_clean_hex(text))
    _require_digest(raw)
    return raw[::-1]


def hex_le(digest: bytes) -> str:
    """Render a digest in internal (little-endian) byte order."""
    _require_digest(digest)
    return digest.hex()


def merkle_root(leaves: Sequence[bytes], *, strict: bool = True) -> bytes:
    """Compute a Bitcoin-style merkle root over ``leaves``.

    ``leaves`` are 32-byte digests in internal byte order. An empty list yields
    the all-zero digest, matching Bitcoin's treatment of an empty commitment.
    """
    for leaf in leaves:
        _require_digest(leaf)

    if not leaves:
        return ZERO_DIGEST

    if strict:
        seen: set[bytes] = set()
        for leaf in leaves:
            if leaf in seen:
                raise IntegrityError(
                    f"duplicate merkle leaf {hex_be(leaf)}: duplicate leaves make the "
                    "root ambiguous (CVE-2012-2459); deduplicate or pass strict=False"
                )
            seen.add(leaf)

    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])  # Bitcoin duplicates the final node
        level = [hash256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def merkle_path(leaves: Sequence[bytes], index: int, *, strict: bool = True) -> list[bytes]:
    """Return the sibling digests proving ``leaves[index]`` is in the root."""
    if not 0 <= index < len(leaves):
        raise IntegrityError(f"merkle leaf index {index} out of range (0..{len(leaves) - 1})")
    for leaf in leaves:
        _require_digest(leaf)
    if strict and len(set(leaves)) != len(leaves):
        raise IntegrityError("duplicate merkle leaves; refusing to build an ambiguous proof")

    path: list[bytes] = []
    level = list(leaves)
    position = index
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        sibling = position ^ 1
        path.append(level[sibling])
        level = [hash256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        position //= 2
    return path


def merkle_verify(leaf: bytes, index: int, path: Iterable[bytes], root: bytes) -> bool:
    """Verify a merkle inclusion proof produced by :func:`merkle_path`."""
    _require_digest(leaf)
    _require_digest(root)
    current = leaf
    position = index
    for sibling in path:
        _require_digest(sibling)
        if position % 2 == 0:
            current = hash256(current + sibling)
        else:
            current = hash256(sibling + current)
        position //= 2
    return current == root


def digest_object(value: object) -> bytes:
    """Canonicalise ``value`` and return its ``hash256`` digest."""
    from .canonical import canonical_bytes  # local import: avoids a cycle

    return hash256(canonical_bytes(value))


def op_return_payload(root: bytes, magic: bytes = b"FORGE1") -> bytes:
    """Build an ``OP_RETURN`` payload anchoring ``root`` to a Bitcoin chain.

    Bitcoin relays ``OP_RETURN`` outputs carrying at most 80 bytes of data, so
    the magic prefix plus a 32-byte root leaves ample headroom. forge only
    *builds* this payload -- it never constructs, signs, or broadcasts a
    transaction, because that would require key custody.
    """
    _require_digest(root)
    payload = magic + root
    if len(payload) > 80:
        raise IntegrityError(f"OP_RETURN payload is {len(payload)} bytes, limit is 80")
    return payload


def _require_digest(digest: bytes) -> None:
    if not isinstance(digest, (bytes, bytearray)):
        raise IntegrityError(f"expected bytes digest, got {type(digest).__name__}")
    if len(digest) != DIGEST_SIZE:
        raise IntegrityError(f"expected a {DIGEST_SIZE}-byte digest, got {len(digest)} bytes")


def _clean_hex(text: str) -> str:
    cleaned = text.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) != DIGEST_SIZE * 2 or any(c not in "0123456789abcdef" for c in cleaned):
        raise IntegrityError(f"not a 32-byte hex digest: {text!r}")
    return cleaned


__all__ = [
    "DIGEST_SIZE",
    "ZERO_DIGEST",
    "sha256",
    "hash256",
    "hex_be",
    "hex_le",
    "from_hex_be",
    "merkle_root",
    "merkle_path",
    "merkle_verify",
    "digest_object",
    "op_return_payload",
]
