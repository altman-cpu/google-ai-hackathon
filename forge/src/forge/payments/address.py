"""SEI address parsing and validation.

SEI has two address surfaces over one chain:

* **Cosmos**: bech32 with the ``sei`` human-readable part, e.g. ``sei1...``
* **EVM**: 20-byte hex with an EIP-55 mixed-case checksum, e.g. ``0x...``

Both are validated here with real checksum arithmetic -- bech32 polymod for the
former, Keccak-256 for the latter. A typo'd payout address is unrecoverable, so
this refuses anything it cannot fully verify rather than passing it through.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..errors import PaymentError
from .keccak import keccak256

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_GENERATOR = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
SEI_HRP = "sei"


@dataclass(frozen=True)
class Address:
    """A validated SEI address."""

    value: str
    kind: str  # "cosmos" | "evm"

    def __str__(self) -> str:
        return self.value


def parse(raw: str) -> Address:
    """Validate ``raw`` as either a Cosmos bech32 or an EVM hex address."""
    if not isinstance(raw, str) or not raw.strip():
        raise PaymentError("address must be a non-empty string")
    candidate = raw.strip()

    if candidate.lower().startswith("0x"):
        return Address(value=_validate_evm(candidate), kind="evm")
    if candidate.lower().startswith(SEI_HRP + "1"):
        return Address(value=_validate_bech32(candidate), kind="cosmos")

    raise PaymentError(
        f"{raw!r} is not a recognisable SEI address: expected a bech32 address "
        "starting 'sei1' or an EVM address starting '0x'"
    )


# ---- bech32 (BIP-173) ----------------------------------------------------


def _bech32_polymod(values: list[int]) -> int:
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for bit in range(5):
            checksum ^= BECH32_GENERATOR[bit] if ((top >> bit) & 1) else 0
    return checksum


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]


def _validate_bech32(candidate: str) -> str:
    # Mixed case is forbidden outright by BIP-173: the checksum is case-folded,
    # so mixed case makes the encoding ambiguous.
    if candidate.lower() != candidate and candidate.upper() != candidate:
        raise PaymentError(f"bech32 address {candidate!r} mixes upper and lower case")
    lowered = candidate.lower()

    if len(lowered) < 8 or len(lowered) > 90:
        raise PaymentError(f"bech32 address has invalid length {len(lowered)} (must be 8..90)")

    separator = lowered.rfind("1")
    if separator < 1:
        raise PaymentError(f"bech32 address {candidate!r} has no human-readable part")

    hrp = lowered[:separator]
    if hrp != SEI_HRP:
        raise PaymentError(
            f"address prefix is {hrp!r}, expected {SEI_HRP!r}; this address is for another chain"
        )

    data_part = lowered[separator + 1:]
    if len(data_part) < 6:
        raise PaymentError("bech32 address is missing its 6-character checksum")

    try:
        data = [BECH32_CHARSET.index(char) for char in data_part]
    except ValueError as exc:
        bad = next(char for char in data_part if char not in BECH32_CHARSET)
        raise PaymentError(
            f"bech32 address contains {bad!r}, which is not in the bech32 alphabet "
            "(note: 1, b, i, and o are excluded to avoid transcription errors)"
        ) from exc

    if _bech32_polymod(_bech32_hrp_expand(hrp) + data) != 1:
        raise PaymentError(
            f"bech32 checksum failed for {candidate!r}. The address is mistyped -- "
            "sending funds to it would lose them."
        )

    # A Cosmos account address decodes to exactly 20 bytes.
    payload = _convert_bits(data[:-6], 5, 8, pad=False)
    if payload is None or len(payload) != 20:
        raise PaymentError(
            f"bech32 payload decodes to {len(payload) if payload else 0} bytes, expected 20"
        )
    return lowered


def _convert_bits(data: list[int], from_bits: int, to_bits: int, pad: bool) -> list[int] | None:
    accumulator = 0
    bits = 0
    out: list[int] = []
    max_value = (1 << to_bits) - 1
    for value in data:
        if value < 0 or (value >> from_bits):
            return None
        accumulator = (accumulator << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            out.append((accumulator >> bits) & max_value)
    if pad:
        if bits:
            out.append((accumulator << (to_bits - bits)) & max_value)
    elif bits >= from_bits or ((accumulator << (to_bits - bits)) & max_value):
        return None
    return out


# ---- EVM / EIP-55 --------------------------------------------------------


def _validate_evm(candidate: str) -> str:
    body = candidate[2:]
    if len(body) != 40:
        raise PaymentError(
            f"EVM address must be 40 hex characters after '0x', got {len(body)}"
        )
    if any(char not in "0123456789abcdefABCDEF" for char in body):
        raise PaymentError(f"EVM address {candidate!r} contains non-hex characters")

    checksummed = to_checksum_address(body)

    # All-lower or all-upper means the sender opted out of the checksum.
    if body == body.lower() or body == body.upper():
        return checksummed

    if "0x" + body != checksummed:
        raise PaymentError(
            f"EIP-55 checksum failed for {candidate!r}\n"
            f"  expected {checksummed}\n"
            "  The address is mistyped, or was copied from a source that corrupted its case."
        )
    return checksummed


def to_checksum_address(body: str) -> str:
    """Apply the EIP-55 mixed-case checksum to a 40-character hex body."""
    lowered = body.lower()
    digest = keccak256(lowered.encode("ascii")).hex()
    out = ["0x"]
    for index, char in enumerate(lowered):
        if char in "0123456789":
            out.append(char)
        else:
            out.append(char.upper() if int(digest[index], 16) >= 8 else char)
    return "".join(out)


__all__ = ["Address", "parse", "to_checksum_address", "SEI_HRP"]
