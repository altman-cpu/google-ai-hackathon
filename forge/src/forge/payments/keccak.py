"""Keccak-256, as used by Ethereum and SEI's EVM surface.

Python's ``hashlib.sha3_256`` is *not* Keccak-256. NIST changed the padding
byte from ``0x01`` to ``0x06`` when SHA-3 was standardised, so the two produce
completely different digests. Ethereum froze on the original Keccak padding,
which means address checksums (EIP-55) need real Keccak.

Rather than add a dependency for one hash, this is a direct implementation of
Keccak-f[1600] with rate 1088 (``r=136`` bytes, ``c=512``) and the original
``0x01``/``0x80`` padding. It is validated in the test suite against the
published empty-string and "abc" vectors.

This is used only for address checksum validation. Nothing security-critical
depends on its performance.
"""

from __future__ import annotations

MASK = (1 << 64) - 1
RATE = 136  # bytes; 1088-bit rate for Keccak-256

_ROTATION = (1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
             27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44)

_PI_LANE = (10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
            15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1)

_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)


def _rotl(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (64 - shift))) & MASK


def _keccak_f(state: list[int]) -> None:
    """The Keccak-f[1600] permutation, applied in place to 25 lanes."""
    for round_constant in _ROUND_CONSTANTS:
        # theta
        column = [
            state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20]
            for i in range(5)
        ]
        for i in range(5):
            diffuse = column[(i + 4) % 5] ^ _rotl(column[(i + 1) % 5], 1)
            for j in range(0, 25, 5):
                state[j + i] ^= diffuse

        # rho and pi
        carry = state[1]
        for i in range(24):
            lane = _PI_LANE[i]
            held = state[lane]
            state[lane] = _rotl(carry, _ROTATION[i])
            carry = held

        # chi
        for j in range(0, 25, 5):
            row = state[j:j + 5]
            for i in range(5):
                state[j + i] = row[i] ^ ((~row[(i + 1) % 5] & MASK) & row[(i + 2) % 5])

        # iota
        state[0] ^= round_constant


def keccak256(data: bytes) -> bytes:
    """Return the 32-byte Keccak-256 digest of ``data``."""
    state = [0] * 25

    # Pad with the original Keccak rule: 0x01 ... 0x80 (not SHA-3's 0x06).
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % RATE != 0:
        padded.append(0x00)
    padded[-1] |= 0x80

    # Absorb
    for offset in range(0, len(padded), RATE):
        block = padded[offset:offset + RATE]
        for lane in range(RATE // 8):
            state[lane] ^= int.from_bytes(block[lane * 8:(lane + 1) * 8], "little")
        _keccak_f(state)

    # Squeeze: 256 bits fit inside a single rate block, so one pass suffices.
    out = bytearray()
    for lane in range(4):
        out += state[lane].to_bytes(8, "little")
    return bytes(out)


def keccak256_hex(data: bytes) -> str:
    return keccak256(data).hex()


__all__ = ["keccak256", "keccak256_hex"]
