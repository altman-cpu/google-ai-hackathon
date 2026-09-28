"""Command line interface.

Every command prints either a human summary or, with ``--json``, a canonical
JSON document suitable for piping into ``jq``. Errors go to stderr and map to
distinct exit codes from :mod:`forge.errors`, so shell scripts can branch on
the failure category.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

from . import __version__, generators, pipeline
from .canonical import canonical_json, loads
from .config import DEFAULT_NETWORK, NETWORKS, Config, Rigor
from .errors import ForgeError, IntegrityError, PaymentError
from .iceberg import Iceberg
from .payments import catalog as catalog_mod
from .payments import gateway
from .signing import manifest as manifest_mod
from .signing import pgp
from .transform import Artifact

PROGRAM = "forge"


# ---- helpers -------------------------------------------------------------


def _config(args: argparse.Namespace) -> Config:
    from . import config as config_mod

    overrides: dict[str, Any] = {}
    for key in ("rigor", "network", "workdir", "payee", "gpg_key"):
        value = getattr(args, key, None)
        if value:
            overrides[key] = value
    if getattr(args, "allow_mainnet", False):
        os.environ["FORGE_ALLOW_MAINNET"] = "1"
    return config_mod.load(overrides)


def _emit(payload: Any, as_json: bool, lines: list[str]) -> None:
    if as_json:
        print(canonical_json(payload))
    else:
        for line in lines:
            print(line)


def _rule(title: str) -> str:
    return f"\n{title}\n" + "-" * len(title)


# ---- commands ------------------------------------------------------------


def cmd_catalog(args: argparse.Namespace) -> int:
    """Publish the price list. No auth, no wallet, no chain access."""
    published = catalog_mod.published_catalog()
    lines = [_rule("What can be paid for, in SEI")]
    lines.append(f"{'CODE':<24} {'UNIT':<8} {'PRICE (usei)':>14}  {'SEI':>12}")
    for item in published["items"]:
        lines.append(
            f"{item['code']:<24} {item['unit']:<8} {item['unit_usei']:>14,}  {item['unit_sei']:>12}"
        )
    lines.append(_rule("Rigor multipliers"))
    for entry in published["rigor_multipliers"]:
        lines.append(f"{entry['rigor']:<24} {entry['multiplier']:>10}  ({entry['basis_points']} bp)")
    lines.append("")
    lines.append("All amounts are integer usei (1 SEI = 1,000,000 usei).")
    lines.append("forge is non-custodial: it never holds a private key.")
    _emit(published, args.json, lines)
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    intent, warnings = pipeline.load_intent(Path(args.intent))
    config = _config(args)
    rigor = pipeline.effective_rigor(intent, config)

    payload = {
        "digest": intent.digest_hex,
        "edges": len(intent.edges),
        "name": intent.name,
        "nodes": len(intent.nodes),
        "rigor": rigor.value,
        "valid": True,
        "warnings": warnings,
    }
    lines = [
        f"intent   {intent.name}",
        f"digest   {intent.digest_hex}",
        f"graph    {len(intent.nodes)} node(s), {len(intent.edges)} edge(s)",
        f"rigor    {rigor.value}",
    ]
    if warnings:
        lines.append(_rule(f"{len(warnings)} warning(s)"))
        lines.extend(f"  ! {warning}" for warning in warnings)
    else:
        lines.append("no warnings")

    pipeline.apply_warning_policy(warnings, rigor)
    _emit(payload, args.json, lines)
    return 0


def cmd_design(args: argparse.Namespace) -> int:
    config = _config(args)
    intent, warnings = pipeline.load_intent(Path(args.intent))
    rigor = pipeline.effective_rigor(intent, config)
    pipeline.apply_warning_policy(warnings, rigor)
    plan = pipeline.design(intent, config, designer=args.designer)

    lines = [
        f"intent    {intent.name}  ({intent.digest_hex[:16]}...)",
        f"designer  {plan.designer}",
        f"plan      {plan.digest_hex[:16]}...",
        _rule("Build order"),
    ]
    for position, step in enumerate(plan.steps, start=1):
        context = step.context()
        flags = [
            f"auth={context['auth']}",
            "idempotent" if context["idempotent"] else "",
            "pii" if context["handles_pii"] else "",
            f"max={context['max_bytes']}B" if context["max_bytes"] else "",
            f"rate={context['rate_limit']}/min" if context["rate_limit"] else "",
        ]
        lines.append(
            f"{position:>2}. {step.id:<20} {step.node.kind:<10} via {step.generator:<16} "
            + " ".join(flag for flag in flags if flag)
        )
    _emit(plan.document(), args.json, lines)
    return 0


def cmd_build(args: argparse.Namespace) -> int:
    config = _config(args)
    result = pipeline.build(
        Path(args.intent),
        config,
        designer=args.designer,
        sign=True if args.sign else (False if args.no_sign else None),
        payee=args.payee,
        tx_hash=args.tx,
        write=not args.dry_run,
        store=not args.no_store,
        out_dir=Path(args.out) if args.out else None,
    )

    lines = [
        f"intent        {result.intent.name}",
        f"intent digest {result.intent.digest_hex}",
        f"plan digest   {result.plan.digest_hex}",
        f"chain root    {result.chain.root_hex}",
        f"merkle root   {result.manifest.merkle_root_hex}",
        f"rigor         {result.rigor.value}",
        f"designer      {result.plan.designer}",
        f"signature     {'present (' + result.signed.signing_key + ')' if result.signed.is_signed else 'none'}",
        _rule(f"{len(result.artifacts)} artifact(s)"),
    ]
    for artifact in result.artifacts:
        lines.append(f"  {artifact.digest_hex[:16]}  {artifact.size:>7}B  {artifact.path}")

    lines.append(_rule("Price"))
    for item in result.quote.items:
        lines.append(
            f"  {item.code:<24} x{item.quantity:<5} {item.amount_usei:>12,} usei"
        )
    lines.append(
        f"  {'subtotal':<24} {'':<6} {result.quote.subtotal_usei:>12,} usei"
    )
    lines.append(
        f"  {'rigor x' + str(result.quote.rigor_basis_points) + 'bp':<24} {'':<6} "
        f"{result.quote.total_usei:>12,} usei  = {result.quote.total_sei_text} SEI"
    )

    if result.payment:
        lines.append(_rule("Payment request"))
        lines.extend("  " + line for line in result.payment.instructions())
    if result.settlement:
        status = "SETTLED" if result.settlement.settled else "NOT SETTLED"
        lines.append(_rule(f"Settlement: {status}"))
        for reason in result.settlement.reasons:
            lines.append(f"  ! {reason}")
        if result.settlement.settled:
            lines.append(f"  {result.settlement.confirmations} confirmation(s)")

    if result.warnings:
        lines.append(_rule(f"{len(result.warnings)} warning(s)"))
        lines.extend(f"  ! {warning}" for warning in result.warnings)

    if result.written:
        lines.append(_rule(f"Wrote {len(result.written)} file(s)"))
        target = args.out or str(config.out_dir)
        lines.extend(f"  {target}/{name}" for name in result.written)
    elif args.dry_run:
        lines.append("\ndry run: nothing written to disk")

    _emit(result.summary(), args.json, lines)
    return 0


def cmd_quote(args: argparse.Namespace) -> int:
    """Price a build without writing anything."""
    config = _config(args)
    result = pipeline.build(
        Path(args.intent),
        config,
        designer=args.designer,
        sign=False if args.no_sign else None,
        payee=args.payee,
        write=False,
        store=False,
    )
    payload: dict[str, Any] = {"quote": result.quote.document()}
    lines = [_rule(f"Quote for {result.intent.name}")]
    for item in result.quote.items:
        lines.append(
            f"  {item.code:<24} x{item.quantity:<5} @{item.unit_usei:>9,} "
            f"= {item.amount_usei:>12,} usei"
        )
    lines.append(f"  {'-' * 60}")
    lines.append(f"  {'subtotal':<32} {result.quote.subtotal_usei:>12,} usei")
    lines.append(
        f"  {'rigor ' + result.quote.rigor + ' (' + str(result.quote.rigor_basis_points) + ' bp)':<32} "
        f"{result.quote.total_usei:>12,} usei"
    )
    lines.append(f"  {'TOTAL':<32} {result.quote.total_sei_text:>12} SEI")

    if result.payment:
        payload["payment_request"] = result.payment.document()
        lines.append("")
        lines.extend("  " + line for line in result.payment.instructions())
        if args.save:
            Path(args.save).write_text(
                canonical_json(result.payment.document()) + "\n", encoding="utf-8"
            )
            lines.append(f"\n  payment request saved to {args.save}")
    else:
        lines.append(
            "\n  No payee configured, so no payment request was issued.\n"
            "  Set FORGE_SEI_PAYEE or pass --payee to get one."
        )
    _emit(payload, args.json, lines)
    return 0


def cmd_verify_payment(args: argparse.Namespace) -> int:
    config = _config(args)
    raw = loads(Path(args.request).read_bytes())
    request = gateway.request_from_document(raw)
    settlement = gateway.verify_payment(config, request, args.tx)

    lines = [
        _rule("Payment verification"),
        f"  network    {config.network.name}"
        + ("  [MAINNET]" if config.network.is_mainnet else "  [testnet]"),
        f"  reference  {settlement.reference}",
        f"  required   {request.amount_sei} SEI to {request.payee}",
    ]
    if settlement.transfer:
        transfer = settlement.transfer
        lines += [
            f"  found      {catalog_mod.format_sei(transfer.amount_usei)} SEI "
            f"to {transfer.recipient}",
            f"  surface    {transfer.surface}  height {transfer.height}  "
            f"{settlement.confirmations} confirmation(s)",
        ]
    lines.append("")
    if settlement.settled:
        lines.append("  SETTLED")
    else:
        lines.append("  NOT SETTLED")
        lines.extend(f"    - {reason}" for reason in settlement.reasons)

    _emit(settlement.document(), args.json, lines)
    return 0 if settlement.settled else PaymentError.exit_code


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify a built tree: integrity first, then authenticity."""
    config = _config(args)
    root = Path(args.dir)
    manifest_path = root / "forge-manifest.json"
    if not manifest_path.exists():
        raise ForgeError(f"no forge-manifest.json in {root}")

    manifest_bytes = manifest_path.read_bytes()
    document = loads(manifest_bytes)

    # Rebuild artifacts from disk exactly as the manifest describes them.
    artifacts: list[Artifact] = []
    missing: list[str] = []
    for entry in document.get("artifacts", []):
        target = root / entry["path"]
        if not target.exists():
            missing.append(entry["path"])
            continue
        artifacts.append(
            Artifact(
                path=entry["path"],
                content=target.read_bytes(),
                mode=int(entry.get("mode", "0644"), 8),
                media_type=entry.get("media_type", "text/plain"),
            )
        )

    problems = manifest_mod.verify_integrity(document, artifacts)
    problems.extend(f"{path}: missing from disk" for path in missing)

    signature_path = root / "forge-manifest.json.asc"
    if signature_path.exists():
        verification = pgp.verify_detached(
            manifest_bytes, signature_path.read_text(encoding="utf-8"), config.gpg_binary
        )
    else:
        verification = pgp.Verification(
            valid=False, status="ABSENT", detail="no forge-manifest.json.asc alongside the manifest"
        )

    integrity_ok = not problems
    payload = {
        "schema": "forge.verification/v1",
        "authenticity": verification.document(),
        "integrity": {"ok": integrity_ok, "problems": problems},
        "manifest_digest": document.get("merkle_root", ""),
        "verified": integrity_ok and verification.valid,
    }

    lines = [
        _rule(f"Verifying {root}"),
        f"  artifacts   {len(artifacts)} checked",
        f"  integrity   {'OK' if integrity_ok else 'FAILED'}",
    ]
    for problem in problems:
        lines.append(f"    - {problem}")
    lines.append(
        f"  signature   {verification.status}"
        + (f"  {verification.fingerprint}" if verification.fingerprint else "")
    )
    if verification.signer:
        lines.append(f"  signer      {verification.signer}")
    if verification.detail and not verification.valid:
        lines.append(f"    {verification.detail}")
    lines.append("")
    if payload["verified"]:
        lines.append("  VERIFIED: contents match the manifest, and the signature is good.")
    elif integrity_ok and not verification.valid:
        lines.append(
            "  UNVERIFIED: contents match the manifest, but the signature does not "
            "check out.\n"
            "  A matching manifest proves nothing on its own -- anyone can write one."
        )
    else:
        lines.append("  FAILED: contents do not match the manifest.")

    _emit(payload, args.json, lines)
    return 0 if payload["verified"] else IntegrityError.exit_code


def cmd_iceberg(args: argparse.Namespace) -> int:
    config = _config(args)
    iceberg = Iceberg(config.iceberg_dir)

    if args.fsck:
        problems = iceberg.fsck()
        payload = {"ok": not problems, "problems": problems}
        lines = [_rule("Iceberg integrity check")]
        lines.extend(f"  - {problem}" for problem in problems)
        lines.append("  healthy" if not problems else f"  {len(problems)} problem(s)")
        _emit(payload, args.json, lines)
        return 0 if not problems else IntegrityError.exit_code

    if args.show:
        tip = iceberg.tip(args.show)
        body = iceberg.body(args.show)
        if args.json:
            print(canonical_json({"tip": tip.document(), "size": len(body)}))
        else:
            sys.stdout.buffer.write(body)
        return 0

    surface = iceberg.surface()
    lines = [
        _rule("Iceberg surface"),
        f"  {surface['object_count']} object(s), {surface['submerged_bytes']:,} bytes submerged",
        "",
        f"  {'DIGEST':<18} {'KIND':<10} {'SIZE':>9}  PATH",
    ]
    for tip in surface["tips"]:
        lines.append(
            f"  {tip['digest'][:16]}.. {tip['kind']:<10} {tip['size']:>9,}  {tip['path']}"
        )
    lines.append("")
    lines.append("  Tips are public metadata. Bodies are whole, unchunked, and")
    lines.append("  addressed only by their full 64-character digest.")
    _emit(surface, args.json, lines)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from .api.server import serve

    config = _config(args)
    serve(config, host=args.host, port=args.port)
    return 0


def cmd_generators(args: argparse.Namespace) -> int:
    names = generators.available()
    _emit({"generators": names}, args.json, [_rule("Generators")] + [f"  {n}" for n in names])
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    """Report what is and is not available in this environment."""
    config = _config(args)
    gpg_ok = pgp.is_available(config.gpg_binary)
    payload = {
        "schema": "forge.doctor/v1",
        "gemini_key": bool(config.gemini_api_key),
        "gpg": {"available": gpg_ok, "version": pgp.version(config.gpg_binary)},
        "mainnet_opt_in": config.allow_mainnet,
        "network": {
            "name": config.network.name,
            "is_mainnet": config.network.is_mainnet,
            "lcd": config.network.lcd,
        },
        "payee": config.payee or "",
        "python": sys.version.split()[0],
        "rigor": config.rigor.value,
        "source_date_epoch": config.source_date_epoch,
        "version": __version__,
    }
    lines = [
        _rule("forge doctor"),
        f"  version            {__version__}",
        f"  python             {payload['python']}",
        f"  rigor              {config.rigor.value}",
        f"  workdir            {config.workdir}",
        f"  SOURCE_DATE_EPOCH  {config.source_date_epoch}",
        "",
        f"  gpg                {'yes -- ' + payload['gpg']['version'] if gpg_ok else 'NOT FOUND (signing unavailable)'}",
        f"  GEMINI_API_KEY     {'set' if config.gemini_api_key else 'not set (deterministic designer only)'}",
        "",
        f"  SEI network        {config.network.name}"
        + ("  *** MAINNET ***" if config.network.is_mainnet else "  (testnet)"),
        f"  LCD                {config.network.lcd}",
        f"  EVM RPC            {config.network.evm_rpc}",
        f"  payee              {config.payee or 'not set (no payment requests will be issued)'}",
        f"  mainnet opt-in     {'YES' if config.allow_mainnet else 'no'}",
        f"  confirmations      {config.min_confirmations}",
        "",
        "  forge holds no private keys. Payment is request-and-verify only.",
    ]
    if config.network.is_mainnet and not config.allow_mainnet:
        lines.append("")
        lines.append("  ! Mainnet selected without FORGE_ALLOW_MAINNET=1; payment ops will refuse.")
    _emit(payload, args.json, lines)
    return 0


# ---- parser --------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description="Design code from network intent. Content-addressed, signed, priced in SEI.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "forge never holds a private key. Payments are issued as requests and\n"
            "verified read-only on chain.\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"{PROGRAM} {__version__}")

    # Global options are attached to both the top-level parser and every
    # subparser, so `forge --json build x` and `forge build x --json` are
    # equivalent. SUPPRESS is what makes that safe: without it the subparser's
    # unset defaults would overwrite whatever the top-level parser captured.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                        help="emit canonical JSON")
    common.add_argument("--rigor", choices=[level.value for level in Rigor],
                        default=argparse.SUPPRESS,
                        help="how hard to fail (default: standard, or FORGE_RIGOR)")
    common.add_argument("--workdir", default=argparse.SUPPRESS,
                        help="state directory (default: .forge)")
    common.add_argument("--network", choices=sorted(NETWORKS), default=argparse.SUPPRESS,
                        help=f"SEI network (default: {DEFAULT_NETWORK}, a testnet)")
    common.add_argument("--allow-mainnet", action="store_true", default=argparse.SUPPRESS,
                        help="permit mainnet operations involving real funds")
    common.add_argument("--payee", default=argparse.SUPPRESS,
                        help="SEI address to receive payment (sei1... or 0x...)")
    common.add_argument("--gpg-key", default=argparse.SUPPRESS,
                        help="key id or fingerprint to sign with")

    # Accept the globals before the subcommand as well as after it.
    for action in common._actions:
        parser._add_action(action)

    subparsers = parser.add_subparsers(dest="command", required=True)

    sub = subparsers.add_parser("catalog", parents=[common],
                                help="show what can be paid for, and the price")
    sub.set_defaults(func=cmd_catalog)

    sub = subparsers.add_parser("validate", parents=[common], help="validate an intent document")
    sub.add_argument("intent")
    sub.set_defaults(func=cmd_validate)

    sub = subparsers.add_parser("design", parents=[common],
                                help="resolve an intent into an ordered build plan")
    sub.add_argument("intent")
    sub.add_argument("--designer", choices=["deterministic", "gemini"], default="deterministic")
    sub.set_defaults(func=cmd_design)

    sub = subparsers.add_parser("build", parents=[common],
                                help="generate, price, sign, and store")
    sub.add_argument("intent")
    sub.add_argument("--designer", choices=["deterministic", "gemini"], default="deterministic")
    sub.add_argument("--out", help="output directory (default: <workdir>/out)")
    sub.add_argument("--sign", action="store_true", help="force signing")
    sub.add_argument("--no-sign", action="store_true", help="skip signing")
    sub.add_argument("--no-store", action="store_true", help="do not file into the iceberg")
    sub.add_argument("--dry-run", action="store_true", help="do everything except write files")
    sub.add_argument("--tx", help="settled payment transaction hash")
    sub.set_defaults(func=cmd_build)

    sub = subparsers.add_parser("quote", parents=[common],
                                help="price a build and issue a payment request")
    sub.add_argument("intent")
    sub.add_argument("--designer", choices=["deterministic", "gemini"], default="deterministic")
    sub.add_argument("--no-sign", action="store_true")
    sub.add_argument("--save", help="write the payment request to this path")
    sub.set_defaults(func=cmd_quote)

    sub = subparsers.add_parser("verify-payment", parents=[common],
                                help="check a payment request against the chain")
    sub.add_argument("--request", required=True, help="payment-request.json")
    sub.add_argument("--tx", required=True, help="transaction hash")
    sub.set_defaults(func=cmd_verify_payment)

    sub = subparsers.add_parser("verify", parents=[common],
                                help="verify a built tree against its signed manifest")
    sub.add_argument("dir")
    sub.set_defaults(func=cmd_verify)

    sub = subparsers.add_parser("iceberg", parents=[common], help="inspect the object store")
    sub.add_argument("--fsck", action="store_true", help="verify every stored object")
    sub.add_argument("--show", metavar="DIGEST", help="write one body to stdout")
    sub.set_defaults(func=cmd_iceberg)

    sub = subparsers.add_parser("serve", parents=[common], help="run the REST API")
    sub.add_argument("--host", default="0.0.0.0")
    sub.add_argument("--port", type=int, default=8787)
    sub.set_defaults(func=cmd_serve)

    sub = subparsers.add_parser("generators", parents=[common], help="list generators")
    sub.set_defaults(func=cmd_generators)

    sub = subparsers.add_parser("doctor", parents=[common], help="report environment readiness")
    sub.set_defaults(func=cmd_doctor)

    return parser


GLOBAL_DEFAULTS: dict[str, Any] = {
    "json": False,
    "rigor": None,
    "workdir": None,
    "network": None,
    "allow_mainnet": False,
    "payee": None,
    "gpg_key": None,
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # SUPPRESS means unspecified globals are simply absent; fill them in once
    # here so every command can read them unconditionally.
    for key, default in GLOBAL_DEFAULTS.items():
        if not hasattr(args, key):
            setattr(args, key, default)
    try:
        return int(args.func(args))
    except ForgeError as exc:
        print(f"{PROGRAM}: {type(exc).__name__.replace('Error', '').lower()}: {exc}",
              file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print(f"\n{PROGRAM}: interrupted", file=sys.stderr)
        return 130
    except BrokenPipeError:
        return 0


__all__ = ["main", "build_parser"]
