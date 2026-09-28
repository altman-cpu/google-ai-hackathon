"""Non-custodial SEI payment gateway.

The custody model, stated plainly, because it is the most important design
decision in this package:

    forge never holds, reads, derives, imports, or transmits a private key.

There is no wallet in this codebase. The flow is:

1. **Quote** -- forge prices the build from the published catalog.
2. **Request** -- forge emits a payment request: payee address, exact integer
   amount, and a memo reference derived from the build's merkle root.
3. **Pay** -- *you* pay, from your own wallet (Compass, Keplr, ``seid``, or an
   EVM wallet). forge is not involved and could not intercept it if it tried.
4. **Verify** -- forge queries the chain read-only and confirms the transfer
   reached the payee, cleared the amount, carried the reference, and has enough
   confirmations.

This is how real crypto payment processors work, and it means the blast radius
of a bug in this package is "a payment is reported unsettled", never "funds
moved". It also means no secret can leak from this repository, because there is
no secret here to leak.

The memo reference binds a payment to one specific build. Paying for build A
does not unlock build B, because B's merkle root -- and therefore its reference
-- is different.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..canonical import canonical_bytes
from ..config import Config
from ..errors import PaymentError
from ..hashing import hash256, hex_be
from . import address as address_mod
from .catalog import Quote, format_sei, price_build
from .sei import SeiClient, Transfer

SCHEMA_REQUEST = "forge.payment.request/v1"
SCHEMA_SETTLEMENT = "forge.payment.settlement/v1"

REFERENCE_PREFIX = "forge:"
REFERENCE_HEX_CHARS = 32  # 128 bits of the reference digest


@dataclass(frozen=True)
class PaymentRequest:
    """An invoice. Contains no key material and confers no spending authority."""

    network: str
    chain_id: str
    payee: str
    payee_kind: str
    amount_usei: int
    reference: str
    quote: Quote
    merkle_root: str
    explorer: str = ""

    @property
    def amount_sei(self) -> str:
        return format_sei(self.amount_usei)

    def document(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_REQUEST,
            "amount_sei": self.amount_sei,
            "amount_usei": self.amount_usei,
            "chain_id": self.chain_id,
            "custody": "none: forge never holds a private key",
            "denom": "usei",
            "explorer": self.explorer,
            "merkle_root": self.merkle_root,
            "network": self.network,
            "payee": self.payee,
            "payee_kind": self.payee_kind,
            "quote": self.quote.document(),
            "reference": self.reference,
        }

    def instructions(self) -> list[str]:
        """Copy-pasteable payment instructions for a human."""
        if self.payee_kind == "cosmos":
            command = (
                f"seid tx bank send <your-key> {self.payee} {self.amount_usei}usei \\\n"
                f"    --note '{self.reference}' --chain-id {self.chain_id}"
            )
        else:
            command = (
                f"Send exactly {self.amount_sei} SEI to {self.payee}\n"
                f"    with calldata 0x{self.reference.encode('utf-8').hex()}\n"
                f"    (the hex-encoded reference string)"
            )
        return [
            f"Pay {self.amount_sei} SEI ({self.amount_usei} usei) on {self.network}",
            f"  to:        {self.payee}",
            f"  reference: {self.reference}   <- must appear in the memo",
            "",
            "  " + command.replace("\n", "\n  "),
            "",
            "  Then: forge verify-payment --tx <hash> --request payment-request.json",
        ]


@dataclass(frozen=True)
class Settlement:
    """The result of checking a payment request against the chain."""

    settled: bool
    reference: str
    reasons: tuple[str, ...] = ()
    transfer: Transfer | None = None
    confirmations: int = 0
    checked_height: int = 0

    def document(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_SETTLEMENT,
            "checked_height": self.checked_height,
            "confirmations": self.confirmations,
            "reasons": list(self.reasons),
            "reference": self.reference,
            "settled": self.settled,
            "transfer": self.transfer.document() if self.transfer else None,
        }


def derive_reference(merkle_root: str, quote: Quote, payee: str) -> str:
    """Derive the memo reference binding a payment to one build.

    Includes the amount and payee as well as the merkle root, so a request
    cannot be replayed against a different build, a different price, or a
    different recipient.
    """
    seed = canonical_bytes(
        {
            "amount_usei": quote.total_usei,
            "merkle_root": merkle_root,
            "payee": payee,
            "purpose": "forge.payment.reference",
        }
    )
    return REFERENCE_PREFIX + hex_be(hash256(seed))[:REFERENCE_HEX_CHARS]


def build_request(
    config: Config,
    *,
    merkle_root: str,
    node_kinds: list[str],
    output_bytes: int,
    designer: str = "deterministic",
    signed: bool = False,
    payee: str | None = None,
    rigor: str | None = None,
) -> PaymentRequest:
    """Price a build and produce a payment request for it.

    ``rigor`` must be the *effective* rigor of the build, which is not
    necessarily ``config.rigor``: an intent document can raise the level via its
    own ``rigor`` floor. Defaulting to ``config.rigor`` here once caused the
    invoice to be priced a tier below the build it was paying for.
    """
    config.require_mainnet_opt_in()

    target = payee or config.payee
    if not target:
        raise PaymentError(
            "no payee address configured.\n"
            "  Set FORGE_SEI_PAYEE to the sei1... or 0x... address that should receive "
            "payment, or pass --payee.\n"
            "  This is a receiving address only; forge never needs the matching key."
        )
    parsed = address_mod.parse(target)

    quote = price_build(
        node_kinds=node_kinds,
        output_bytes=output_bytes,
        rigor=rigor or config.rigor.value,
        designer=designer,
        signed=signed,
    )
    reference = derive_reference(merkle_root, quote, parsed.value)

    return PaymentRequest(
        network=config.network.name,
        chain_id=config.network.chain_id,
        payee=parsed.value,
        payee_kind=parsed.kind,
        amount_usei=quote.total_usei,
        reference=reference,
        quote=quote,
        merkle_root=merkle_root,
        explorer=config.network.explorer,
    )


def verify_payment(config: Config, request: PaymentRequest, tx_hash: str) -> Settlement:
    """Check the chain for a transfer satisfying ``request``.

    Every condition is checked and *all* failures are collected, so a payer
    sees every problem at once instead of fixing them one round-trip at a time.
    """
    config.require_mainnet_opt_in()
    client = SeiClient(config.network, timeout=config.http_timeout)

    transfer = client.find_transfer(tx_hash)
    reasons: list[str] = []

    if not transfer.succeeded:
        reasons.append("the transaction executed but failed on chain")

    if not _same_address(transfer.recipient, request.payee):
        reasons.append(
            f"paid to {transfer.recipient or '(none)'}, but the request names {request.payee}"
        )

    if transfer.amount_usei < request.amount_usei:
        shortfall = request.amount_usei - transfer.amount_usei
        reasons.append(
            f"underpaid by {shortfall} usei "
            f"({format_sei(transfer.amount_usei)} SEI paid, "
            f"{request.amount_sei} SEI required)"
        )

    if request.reference not in (transfer.memo or ""):
        reasons.append(
            f"memo does not contain the reference {request.reference!r} "
            f"(memo was {transfer.memo!r}); without it this payment cannot be "
            "matched to this build"
        )

    height = 0
    confirmations = 0
    try:
        height = client.latest_height()
        confirmations = max(0, height - transfer.height + 1) if transfer.height else 0
    except Exception as exc:  # noqa: BLE001 - height is advisory, never fatal
        reasons.append(f"could not read chain height to count confirmations: {exc}")

    if confirmations < config.min_confirmations:
        reasons.append(
            f"{confirmations} confirmation(s), but {config.min_confirmations} required "
            "(raise FORGE_MIN_CONFIRMATIONS for larger amounts)"
        )

    return Settlement(
        settled=not reasons,
        reference=request.reference,
        reasons=tuple(reasons),
        transfer=transfer,
        confirmations=confirmations,
        checked_height=height,
    )


def request_from_document(raw: dict[str, Any]) -> PaymentRequest:
    """Rehydrate a :class:`PaymentRequest` from its stored JSON form."""
    if not isinstance(raw, dict) or raw.get("schema") != SCHEMA_REQUEST:
        raise PaymentError(f"not a {SCHEMA_REQUEST} document")

    quote_doc = raw.get("quote") or {}
    from .catalog import LineItem  # local import keeps the module import graph flat

    quote = Quote(
        items=tuple(
            LineItem(
                code=str(item["code"]),
                description=str(item.get("description", "")),
                quantity=int(item["quantity"]),
                unit_usei=int(item["unit_usei"]),
            )
            for item in quote_doc.get("items", [])
        ),
        rigor=str(quote_doc.get("rigor", "standard")),
        rigor_basis_points=int(quote_doc.get("rigor_basis_points", 10_000)),
    )
    return PaymentRequest(
        network=str(raw["network"]),
        chain_id=str(raw["chain_id"]),
        payee=str(raw["payee"]),
        payee_kind=str(raw.get("payee_kind", "cosmos")),
        amount_usei=int(raw["amount_usei"]),
        reference=str(raw["reference"]),
        quote=quote,
        merkle_root=str(raw.get("merkle_root", "")),
        explorer=str(raw.get("explorer", "")),
    )


def _same_address(left: str, right: str) -> bool:
    """Compare addresses case-insensitively; EVM case carries no meaning."""
    return (left or "").strip().lower() == (right or "").strip().lower()


__all__ = [
    "SCHEMA_REQUEST",
    "SCHEMA_SETTLEMENT",
    "PaymentRequest",
    "Settlement",
    "derive_reference",
    "build_request",
    "verify_payment",
    "request_from_document",
]
