"""What can be paid for, and what it costs.

This is the answer to "easy access to what can be paid for": a single published
price list, queryable without authentication, without a wallet, and without
touching the chain. ``forge catalog`` prints it; ``GET /v1/catalog`` serves it.

**All arithmetic is integer ``usei``** (1 SEI = 1,000,000 usei). No floats
appear anywhere in the pricing path. Floating-point money is how you end up
charging someone 0.30000000000000004 SEI, and because prices are committed into
a signed manifest, a rounding difference between two machines would break the
signature. Percentages are expressed in basis points and applied with integer
division, rounding up so the operator is never shortchanged by truncation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from ..config import USEI_PER_SEI, Rigor
from ..errors import PaymentError

DENOM = "usei"

# Flat fee for any build, covering validation and manifest construction.
BUILD_BASE_USEI = 50_000

# Per-node price by kind. A model node costs more because it implies inference
# wiring; a store costs less because it is mostly a schema.
NODE_PRICE_USEI: dict[str, int] = {
    "endpoint": 25_000,
    "gateway": 20_000,
    "model": 40_000,
    "service": 15_000,
    "store": 10_000,
    "worker": 15_000,
}

# Output volume, charged per kibibyte, rounded up.
PER_KIB_USEI = 100

# Optional extras.
GEMINI_DESIGNER_USEI = 30_000
SIGNATURE_USEI = 5_000

# Rigor multiplier in basis points (10_000 bp = 1.00x).
RIGOR_BASIS_POINTS: dict[str, int] = {
    Rigor.LAX.value: 7_500,
    Rigor.STANDARD.value: 10_000,
    Rigor.STRICT.value: 15_000,
    Rigor.EXTREME.value: 25_000,
}


@dataclass(frozen=True)
class LineItem:
    code: str
    description: str
    quantity: int
    unit_usei: int

    @property
    def amount_usei(self) -> int:
        return self.quantity * self.unit_usei

    def document(self) -> dict[str, Any]:
        return {
            "amount_usei": self.amount_usei,
            "code": self.code,
            "description": self.description,
            "quantity": self.quantity,
            "unit_usei": self.unit_usei,
        }


@dataclass(frozen=True)
class Quote:
    """An itemised, integer-only price for one build."""

    items: tuple[LineItem, ...]
    rigor: str
    rigor_basis_points: int

    @property
    def subtotal_usei(self) -> int:
        return sum(item.amount_usei for item in self.items)

    @property
    def total_usei(self) -> int:
        # Ceiling division keeps the total integral without ever rounding down.
        scaled = self.subtotal_usei * self.rigor_basis_points
        return -(-scaled // 10_000)

    @property
    def total_sei_text(self) -> str:
        """Human-readable SEI amount, rendered from integers only."""
        return format_sei(self.total_usei)

    def document(self) -> dict[str, Any]:
        return {
            "schema": "forge.quote/v1",
            "denom": DENOM,
            "items": [item.document() for item in self.items],
            "rigor": self.rigor,
            "rigor_basis_points": self.rigor_basis_points,
            "subtotal_usei": self.subtotal_usei,
            "total_sei": self.total_sei_text,
            "total_usei": self.total_usei,
        }


def format_sei(usei: int) -> str:
    """Render ``usei`` as a SEI decimal string using integer arithmetic only."""
    if usei < 0:
        raise PaymentError(f"amount must be non-negative, got {usei}")
    whole, fraction = divmod(usei, USEI_PER_SEI)
    return f"{whole}.{fraction:06d}"


def parse_sei(text: str) -> int:
    """Parse a SEI decimal string into integer usei, refusing sub-usei precision."""
    cleaned = text.strip()
    if not cleaned:
        raise PaymentError("empty SEI amount")
    negative = cleaned.startswith("-")
    if negative:
        raise PaymentError("SEI amount must be non-negative")
    if "." not in cleaned:
        whole, fraction = cleaned, ""
    else:
        whole, _, fraction = cleaned.partition(".")
    if not whole.isdigit() or (fraction and not fraction.isdigit()):
        raise PaymentError(f"{text!r} is not a decimal SEI amount")
    if len(fraction) > 6:
        raise PaymentError(
            f"{text!r} has more than 6 decimal places; SEI's base unit is usei "
            "(1 SEI = 1,000,000 usei) and forge will not round your money"
        )
    return int(whole) * USEI_PER_SEI + int(fraction.ljust(6, "0") or 0)


def price_build(
    *,
    node_kinds: Sequence[str],
    output_bytes: int,
    rigor: str,
    designer: str = "deterministic",
    signed: bool = False,
) -> Quote:
    """Compute an itemised quote for a build."""
    if rigor not in RIGOR_BASIS_POINTS:
        raise PaymentError(
            f"unknown rigor {rigor!r}; expected one of: {', '.join(sorted(RIGOR_BASIS_POINTS))}"
        )
    if output_bytes < 0:
        raise PaymentError("output_bytes must be non-negative")

    items: list[LineItem] = [
        LineItem(
            code="build.base",
            description="Intent validation, plan resolution, and manifest construction",
            quantity=1,
            unit_usei=BUILD_BASE_USEI,
        )
    ]

    counts: dict[str, int] = {}
    for kind in node_kinds:
        if kind not in NODE_PRICE_USEI:
            raise PaymentError(f"no price defined for node kind {kind!r}")
        counts[kind] = counts.get(kind, 0) + 1
    for kind in sorted(counts):
        items.append(
            LineItem(
                code=f"node.{kind}",
                description=f"Code generation for {kind} nodes",
                quantity=counts[kind],
                unit_usei=NODE_PRICE_USEI[kind],
            )
        )

    if output_bytes:
        kib = -(-output_bytes // 1024)  # ceiling
        items.append(
            LineItem(
                code="output.kib",
                description="Generated output, per KiB (rounded up)",
                quantity=kib,
                unit_usei=PER_KIB_USEI,
            )
        )

    if designer == "gemini":
        items.append(
            LineItem(
                code="designer.gemini",
                description="Gemini-assisted parameter inference",
                quantity=1,
                unit_usei=GEMINI_DESIGNER_USEI,
            )
        )

    if signed:
        items.append(
            LineItem(
                code="manifest.signature",
                description="Detached OpenPGP signature over the build manifest",
                quantity=1,
                unit_usei=SIGNATURE_USEI,
            )
        )

    return Quote(
        items=tuple(items),
        rigor=rigor,
        rigor_basis_points=RIGOR_BASIS_POINTS[rigor],
    )


def published_catalog() -> dict[str, Any]:
    """The full, public price list. No auth, no wallet, no chain access."""
    return {
        "schema": "forge.catalog/v1",
        "denom": DENOM,
        "usei_per_sei": USEI_PER_SEI,
        "note": (
            "All prices are integer usei. Totals are subtotal * rigor_basis_points / 10000, "
            "rounded up. forge is non-custodial: it issues payment requests and verifies "
            "settlement read-only, and never holds a private key."
        ),
        "items": [
            {
                "code": "build.base",
                "description": "Flat fee per build",
                "unit": "build",
                "unit_usei": BUILD_BASE_USEI,
                "unit_sei": format_sei(BUILD_BASE_USEI),
            },
            *[
                {
                    "code": f"node.{kind}",
                    "description": f"Code generation for one {kind} node",
                    "unit": "node",
                    "unit_usei": price,
                    "unit_sei": format_sei(price),
                }
                for kind, price in sorted(NODE_PRICE_USEI.items())
            ],
            {
                "code": "output.kib",
                "description": "Generated output volume, per KiB, rounded up",
                "unit": "KiB",
                "unit_usei": PER_KIB_USEI,
                "unit_sei": format_sei(PER_KIB_USEI),
            },
            {
                "code": "designer.gemini",
                "description": "Gemini-assisted parameter inference (optional)",
                "unit": "build",
                "unit_usei": GEMINI_DESIGNER_USEI,
                "unit_sei": format_sei(GEMINI_DESIGNER_USEI),
            },
            {
                "code": "manifest.signature",
                "description": "Detached OpenPGP signature over the manifest (optional)",
                "unit": "build",
                "unit_usei": SIGNATURE_USEI,
                "unit_sei": format_sei(SIGNATURE_USEI),
            },
        ],
        "rigor_multipliers": [
            {
                "rigor": rigor,
                "basis_points": bp,
                "multiplier": f"{bp // 10_000}.{bp % 10_000:04d}x",
            }
            for rigor, bp in sorted(RIGOR_BASIS_POINTS.items(), key=lambda kv: kv[1])
        ],
    }


__all__ = [
    "DENOM",
    "BUILD_BASE_USEI",
    "NODE_PRICE_USEI",
    "PER_KIB_USEI",
    "RIGOR_BASIS_POINTS",
    "LineItem",
    "Quote",
    "format_sei",
    "parse_sei",
    "price_build",
    "published_catalog",
]
