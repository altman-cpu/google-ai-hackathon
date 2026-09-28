"""The build pipeline: intent in, signed and priced artifacts out.

Stages, in order:

1. **Parse** the intent document and validate the network graph.
2. **Gate** on rigor -- at ``strict`` and above, warnings are failures.
3. **Design**: resolve the graph into a topologically ordered plan.
4. **Generate**: run each step's generator, wrapping the output in a chained
   :class:`~forge.transform.TransformObject`.
5. **Reproduce** (``strict``+): run generation a second time and require an
   identical chain root. A generator that reads a clock or a PRNG dies here.
6. **Price**: quote the build and, if a payee is configured, emit a payment
   request bound to the build's merkle root.
7. **Settle** (``extreme``): require an on-chain payment before any artifact
   touches the filesystem.
8. **Sign**: build the manifest and attach a detached OpenPGP signature
   (mandatory at ``extreme``).
9. **Store**: file everything in the iceberg and, optionally, write the tree.

Every stage is separable. The CLI exposes each one so you can inspect the
output of any stage without running the next.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import design as design_mod
from . import generators
from . import intent as intent_mod
from .canonical import loads
from .config import Config, Rigor
from .errors import ForgeError, GeneratorError, IntegrityError, PaymentError, PolicyError
from .hashing import hex_be, merkle_root
from .iceberg import Iceberg
from .intent import Intent
from .llm import deterministic as deterministic_designer
from .llm import gemini as gemini_designer
from .payments import gateway
from .payments.catalog import Quote, price_build
from .payments.gateway import PaymentRequest, Settlement
from .signing import manifest as manifest_mod
from .signing import pgp
from .signing.manifest import Manifest, SignedManifest
from .transform import Artifact, TransformChain, TransformObject, collect_artifacts


@dataclass
class BuildResult:
    """Everything one build produced."""

    intent: Intent
    plan: design_mod.Plan
    chain: TransformChain
    manifest: Manifest
    signed: SignedManifest
    quote: Quote
    rigor: Rigor
    warnings: list[str] = field(default_factory=list)
    payment: PaymentRequest | None = None
    settlement: Settlement | None = None
    written: list[str] = field(default_factory=list)
    stored: list[str] = field(default_factory=list)

    @property
    def artifacts(self) -> list[Artifact]:
        return self.chain.artifacts

    def summary(self) -> dict[str, Any]:
        return {
            "schema": "forge.build/v1",
            "artifact_count": len(self.artifacts),
            "chain_root": self.chain.root_hex,
            "designer": self.plan.designer,
            "intent_digest": self.intent.digest_hex,
            "intent_name": self.intent.name,
            "manifest_digest": self.manifest.digest_hex,
            "merkle_root": self.manifest.merkle_root_hex,
            "payment": self.payment.document() if self.payment else None,
            "plan_digest": self.plan.digest_hex,
            "quote": self.quote.document(),
            "rigor": self.rigor.value,
            "settlement": self.settlement.document() if self.settlement else None,
            "signed": self.signed.is_signed,
            "stored": self.stored,
            "total_bytes": sum(a.size for a in self.artifacts),
            "warnings": self.warnings,
            "written": self.written,
        }


# ---- stage 1: parse ------------------------------------------------------


def load_intent(source: Path | str | dict[str, Any]) -> tuple[Intent, list[str]]:
    """Read and validate an intent document from a path or an in-memory dict."""
    if isinstance(source, dict):
        return intent_mod.parse(source)
    path = Path(source)
    if not path.exists():
        raise ForgeError(f"intent file not found: {path}")
    return intent_mod.parse(loads(path.read_bytes()))


def effective_rigor(intent: Intent, config: Config) -> Rigor:
    """Resolve the rigor to apply.

    The intent's own ``rigor`` acts as a *floor*, never a ceiling. An author who
    marks a network ``extreme`` cannot have that silently relaxed by someone
    running the build with a laxer flag -- but it can always be raised.
    """
    resolved = config.rigor
    if intent.rigor:
        try:
            demanded = Rigor(intent.rigor.lower())
        except ValueError as exc:
            raise PolicyError(
                f"intent declares unknown rigor {intent.rigor!r}; expected one of: "
                + ", ".join(level.value for level in Rigor)
            ) from exc
        if demanded.rank > resolved.rank:
            resolved = demanded
    return resolved


# ---- stage 2: gate -------------------------------------------------------


def apply_warning_policy(warnings: list[str], rigor: Rigor) -> None:
    if warnings and rigor.warnings_are_errors:
        listed = "\n".join(f"    - {warning}" for warning in warnings)
        raise PolicyError(
            f"{len(warnings)} warning(s), and rigor={rigor.value} treats warnings as errors:\n"
            f"{listed}\n"
            "  Fix them, or build at rigor=standard."
        )


# ---- stage 3: design -----------------------------------------------------


def design(intent: Intent, config: Config, *, designer: str = "deterministic") -> design_mod.Plan:
    """Resolve the intent graph into an ordered plan."""
    if designer == "gemini":
        overrides = gemini_designer.propose(
            intent,
            api_key=config.gemini_api_key or "",
            model=config.gemini_model,
            timeout=config.http_timeout,
        )
    elif designer == "deterministic":
        overrides = deterministic_designer.propose(intent)
    else:
        raise ForgeError(
            f"unknown designer {designer!r}; expected 'deterministic' or 'gemini'"
        )
    return design_mod.resolve(intent, designer=designer, overrides=overrides)


# ---- stage 4: generate ---------------------------------------------------


def generate(plan: design_mod.Plan, rigor: Rigor, *, source_date_epoch: int = 0) -> TransformChain:
    """Run every generator, chaining each step's transform onto its producers."""
    transforms: list[TransformObject] = []
    digest_by_node: dict[str, str] = {}

    for step in plan.steps:
        generator = generators.get(step.generator)
        try:
            artifacts = generator(step, plan)
        except ForgeError:
            raise
        except Exception as exc:  # noqa: BLE001 - convert to the forge taxonomy
            raise GeneratorError(
                f"generator {step.generator!r} failed on node {step.id!r}: "
                f"{type(exc).__name__}: {exc}"
            ) from exc

        if not artifacts:
            raise GeneratorError(
                f"generator {step.generator!r} produced nothing for node {step.id!r}"
            )

        # Parents are the transforms of this node's upstream producers, so the
        # DAG mirrors the intent graph's data flow.
        parents = sorted(
            digest_by_node[edge.source]
            for edge in step.inbound
            if edge.source in digest_by_node
        )

        transform = TransformObject(
            operation=f"generate:{step.generator}",
            inputs=(plan.intent.digest_hex,),
            params={
                "generator": step.generator,
                "kind": step.node.kind,
                "node": step.id,
                "resolved": step.context(),
            },
            outputs=tuple(artifacts),
            parents=tuple(parents),
            timestamp=source_date_epoch,
            rigor=rigor.value,
        )
        transforms.append(transform)
        digest_by_node[step.id] = transform.digest_hex

    chain = TransformChain(transforms=tuple(transforms))
    chain.verify_links()
    return chain


# ---- stage 5: reproducibility --------------------------------------------


def check_reproducible(plan: design_mod.Plan, rigor: Rigor, expected_root: str,
                       *, source_date_epoch: int = 0) -> None:
    """Regenerate and require an identical chain root."""
    second = generate(plan, rigor, source_date_epoch=source_date_epoch)
    if second.root_hex != expected_root:
        raise IntegrityError(
            "build is not reproducible: regenerating the same plan produced a different root\n"
            f"    first  {expected_root}\n"
            f"    second {second.root_hex}\n"
            "  A generator is reading a clock, a PRNG, the environment, or unordered state."
        )


# ---- stages 6-9: the whole thing -----------------------------------------


def build(
    source: Path | str | dict[str, Any],
    config: Config,
    *,
    designer: str = "deterministic",
    sign: bool | None = None,
    payee: str | None = None,
    tx_hash: str | None = None,
    write: bool = False,
    store: bool = True,
    out_dir: Path | None = None,
) -> BuildResult:
    """Run the full pipeline."""
    intent, warnings = load_intent(source)
    rigor = effective_rigor(intent, config)
    apply_warning_policy(warnings, rigor)

    plan = design(intent, config, designer=designer)

    chain = generate(plan, rigor, source_date_epoch=config.source_date_epoch)
    artifacts = collect_artifacts(chain.transforms)

    if rigor.requires_reproducibility_check:
        check_reproducible(plan, rigor, chain.root_hex,
                           source_date_epoch=config.source_date_epoch)

    total_bytes = sum(artifact.size for artifact in artifacts)
    node_kinds = [step.node.kind for step in plan.steps]
    want_signature = rigor.requires_signature if sign is None else sign

    quote = price_build(
        node_kinds=node_kinds,
        output_bytes=total_bytes,
        rigor=rigor.value,
        designer=designer,
        signed=want_signature,
    )

    # ---- payment -----------------------------------------------------
    merkle_root_hex = hex_be(merkle_root([a.digest for a in artifacts], strict=True))
    payment: PaymentRequest | None = None
    settlement: Settlement | None = None

    target_payee = payee or config.payee
    if target_payee:
        payment = gateway.build_request(
            config,
            merkle_root=merkle_root_hex,
            node_kinds=node_kinds,
            output_bytes=total_bytes,
            designer=designer,
            signed=want_signature,
            payee=target_payee,
            rigor=rigor.value,
        )
        # The invoice and the quote are computed by separate code paths, so
        # assert they agree. If they ever diverge the user is being billed for a
        # different build than the one they were shown -- refuse rather than
        # pick one. (This check exists because they did diverge once, when the
        # gateway defaulted to config.rigor instead of the effective rigor.)
        if payment.amount_usei != quote.total_usei:
            raise PaymentError(
                "internal pricing inconsistency: the quote shown "
                f"({quote.total_usei} usei) does not match the payment request "
                f"({payment.amount_usei} usei). Refusing to issue an invoice."
            )
        if tx_hash:
            settlement = gateway.verify_payment(config, payment, tx_hash)

    if rigor.requires_settled_payment:
        if payment is None:
            raise PolicyError(
                f"rigor={rigor.value} requires a settled payment before artifacts are "
                "written, but no payee is configured.\n"
                "  Set FORGE_SEI_PAYEE (or pass --payee) and pay the resulting request."
            )
        if settlement is None:
            raise PolicyError(
                f"rigor={rigor.value} requires a settled payment.\n"
                f"  Amount:    {payment.amount_sei} SEI ({payment.amount_usei} usei)\n"
                f"  Payee:     {payment.payee}\n"
                f"  Reference: {payment.reference}\n"
                "  Pay it, then re-run with --tx <hash>."
            )
        if not settlement.settled:
            listed = "\n".join(f"    - {reason}" for reason in settlement.reasons)
            raise PolicyError(f"payment did not settle:\n{listed}")

    # ---- manifest and signature ---------------------------------------
    manifest = manifest_mod.build(
        intent_name=intent.name,
        intent_digest=intent.digest_hex,
        plan_digest=plan.digest_hex,
        chain_root=chain.root_hex,
        artifacts=artifacts,
        rigor=rigor.value,
        source_date_epoch=config.source_date_epoch,
        payment=payment.document() if payment else None,
        designer=designer,
        notes={"warnings": warnings} if warnings else {},
    )

    signature_armored: str | None = None
    signing_key = ""
    if want_signature:
        if not pgp.is_available(config.gpg_binary) and not rigor.requires_signature:
            warnings.append(
                f"{config.gpg_binary} is not installed; the manifest is unsigned"
            )
        else:
            signature = pgp.sign_detached(
                manifest.bytes(), config.gpg_key, config.gpg_binary
            )
            signature_armored = signature.armored
            signing_key = signature.key_id

    signed = SignedManifest(
        manifest=manifest,
        signature_armored=signature_armored,
        signing_key=signing_key,
    )

    result = BuildResult(
        intent=intent,
        plan=plan,
        chain=chain,
        manifest=manifest,
        signed=signed,
        quote=quote,
        rigor=rigor,
        warnings=warnings,
        payment=payment,
        settlement=settlement,
    )

    # ---- persistence ---------------------------------------------------
    if store:
        result.stored = _store(config, result)
    if write:
        result.written = _write_tree(out_dir or config.out_dir, result)

    return result


def _store(config: Config, result: BuildResult) -> list[str]:
    """File the build into the iceberg: tips public, bodies submerged."""
    iceberg = Iceberg(config.iceberg_dir)
    iceberg.ensure()
    stored: list[str] = []

    for artifact in result.artifacts:
        tip = iceberg.put(
            artifact.content,
            kind="artifact",
            media_type=artifact.media_type,
            path=artifact.path,
            labels={"intent": result.intent.name},
            digest=artifact.digest_hex,
        )
        stored.append(tip.digest)

    for kind, document in (
        ("intent", result.intent.document()),
        ("plan", result.plan.document()),
        ("chain", result.chain.document()),
        ("manifest", result.manifest.document()),
    ):
        tip = iceberg.put_document(
            document, kind="document", path=f"{result.intent.name}.{kind}.json",
            labels={"intent": result.intent.name, "role": kind},
        )
        stored.append(tip.digest)

    return stored


def _write_tree(out_dir: Path, result: BuildResult) -> list[str]:
    """Materialise artifacts, the manifest, and the signature on disk."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    for artifact in result.artifacts:
        target = out_dir / artifact.path
        # Belt and braces: Artifact already rejects traversal, but a path that
        # escapes the output root must never be writable.
        resolved = target.resolve()
        if not str(resolved).startswith(str(out_dir.resolve())):
            raise IntegrityError(f"artifact {artifact.path!r} would escape the output directory")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(artifact.content)
        target.chmod(artifact.mode)
        written.append(artifact.path)

    manifest_path = out_dir / "forge-manifest.json"
    manifest_path.write_bytes(result.manifest.bytes())
    written.append("forge-manifest.json")

    if result.signed.is_signed and result.signed.signature_armored:
        signature_path = out_dir / "forge-manifest.json.asc"
        signature_path.write_text(result.signed.signature_armored, encoding="utf-8")
        written.append("forge-manifest.json.asc")

    if result.payment:
        from .canonical import canonical_bytes

        payment_path = out_dir / "payment-request.json"
        payment_path.write_bytes(canonical_bytes(result.payment.document()) + b"\n")
        written.append("payment-request.json")

    return written


__all__ = [
    "BuildResult",
    "load_intent",
    "effective_rigor",
    "apply_warning_policy",
    "design",
    "generate",
    "check_reproducible",
    "build",
]
