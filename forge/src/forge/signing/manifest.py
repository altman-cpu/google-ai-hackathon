"""The signed manifest: one document committing to an entire build.

A manifest carries, in canonical form:

* the intent digest and plan digest that produced the build
* every artifact tip (path, size, media type, digest) -- never content
* the Bitcoin-style merkle root over artifact digests
* the transform-chain root
* an ``OP_RETURN`` payload that could anchor that root to a Bitcoin chain
* the payment request or settlement, when one applies

The manifest is then signed with a detached OpenPGP signature. Verification is
two independent steps, and both must pass:

1. **Integrity** -- recompute every digest and the merkle root from the
   artifacts on disk and compare against the manifest.
2. **Authenticity** -- check the detached signature over the manifest bytes.

Step 1 without step 2 tells you the files match a manifest that anyone could
have written. Step 2 without step 1 tells you someone signed a document that
might describe different files. Only together do they mean anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from ..canonical import canonical_bytes
from ..errors import IntegrityError
from ..hashing import digest_object, hex_be, merkle_root, op_return_payload
from ..transform import Artifact

SCHEMA_MANIFEST = "forge.manifest/v1"
ANCHOR_MAGIC = b"FORGE1"
PRODUCER = "forge/0.1.0"


@dataclass(frozen=True)
class Manifest:
    """An unsigned build manifest."""

    intent_name: str
    intent_digest: str
    plan_digest: str
    chain_root: str
    artifacts: tuple[Artifact, ...]
    rigor: str
    source_date_epoch: int = 0
    payment: dict[str, Any] | None = None
    designer: str = "deterministic"
    notes: dict[str, Any] = field(default_factory=dict)

    @property
    def artifact_leaves(self) -> list[bytes]:
        return [artifact.digest for artifact in sorted(self.artifacts, key=lambda a: a.path)]

    @property
    def merkle_root(self) -> bytes:
        return merkle_root(self.artifact_leaves, strict=True)

    @property
    def merkle_root_hex(self) -> str:
        return hex_be(self.merkle_root)

    def document(self) -> dict[str, Any]:
        """The canonical manifest. These exact bytes are what gets signed."""
        return {
            "schema": SCHEMA_MANIFEST,
            "anchor": {
                "chain": "bitcoin",
                "magic": ANCHOR_MAGIC.decode("ascii"),
                "op_return_hex": op_return_payload(self.merkle_root, ANCHOR_MAGIC).hex(),
                "note": "payload only; forge never builds, signs, or broadcasts a transaction",
            },
            "artifacts": [artifact.tip() for artifact in sorted(self.artifacts, key=lambda a: a.path)],
            "chain_root": self.chain_root,
            "designer": self.designer,
            "hash": "sha256d",
            "intent": {"digest": self.intent_digest, "name": self.intent_name},
            "merkle_root": self.merkle_root_hex,
            "notes": self.notes,
            "payment": self.payment,
            "plan_digest": self.plan_digest,
            "producer": PRODUCER,
            "rigor": self.rigor,
            "source_date_epoch": self.source_date_epoch,
            "total_bytes": sum(artifact.size for artifact in self.artifacts),
        }

    def bytes(self) -> bytes:
        """Canonical bytes, with a trailing newline so the file is POSIX-clean.

        The newline is part of the signed payload. Verifiers must read the file
        whole, byte for byte -- do not strip it.
        """
        return canonical_bytes(self.document()) + b"\n"

    @property
    def digest_hex(self) -> str:
        return hex_be(digest_object(self.document()))


@dataclass(frozen=True)
class SignedManifest:
    """A manifest plus its detached signature (which may be absent)."""

    manifest: Manifest
    signature_armored: str | None = None
    signing_key: str = ""

    @property
    def is_signed(self) -> bool:
        return bool(self.signature_armored)

    def sidecar(self) -> dict[str, Any]:
        """Metadata describing the signature, stored next to the manifest."""
        return {
            "schema": "forge.signature/v1",
            "algorithm": "openpgp-detached-sha256",
            "manifest_digest": self.manifest.digest_hex,
            "merkle_root": self.manifest.merkle_root_hex,
            "signed": self.is_signed,
            "signing_key": self.signing_key,
        }


def build(
    *,
    intent_name: str,
    intent_digest: str,
    plan_digest: str,
    chain_root: str,
    artifacts: Sequence[Artifact],
    rigor: str,
    source_date_epoch: int = 0,
    payment: dict[str, Any] | None = None,
    designer: str = "deterministic",
    notes: dict[str, Any] | None = None,
) -> Manifest:
    """Assemble a manifest, rejecting duplicate artifact paths."""
    paths = [artifact.path for artifact in artifacts]
    duplicates = sorted({path for path in paths if paths.count(path) > 1})
    if duplicates:
        raise IntegrityError("manifest would contain duplicate paths: " + ", ".join(duplicates))
    return Manifest(
        intent_name=intent_name,
        intent_digest=intent_digest,
        plan_digest=plan_digest,
        chain_root=chain_root,
        artifacts=tuple(sorted(artifacts, key=lambda a: a.path)),
        rigor=rigor,
        source_date_epoch=source_date_epoch,
        payment=payment,
        designer=designer,
        notes=notes or {},
    )


def verify_integrity(manifest_doc: dict[str, Any], artifacts: Sequence[Artifact]) -> list[str]:
    """Recompute digests from ``artifacts`` and diff against ``manifest_doc``.

    Returns a list of problems; empty means the artifacts on disk are exactly
    what the manifest describes.
    """
    problems: list[str] = []
    recorded = {entry["path"]: entry for entry in manifest_doc.get("artifacts", [])}
    actual = {artifact.path: artifact for artifact in artifacts}

    for path in sorted(set(recorded) - set(actual)):
        problems.append(f"{path}: listed in the manifest but missing on disk")
    for path in sorted(set(actual) - set(recorded)):
        problems.append(f"{path}: present on disk but absent from the manifest")

    for path in sorted(set(recorded) & set(actual)):
        entry = recorded[path]
        artifact = actual[path]
        if entry["digest"] != artifact.digest_hex:
            problems.append(
                f"{path}: digest mismatch\n"
                f"      manifest {entry['digest']}\n"
                f"      on disk  {artifact.digest_hex}"
            )
        elif int(entry["size"]) != artifact.size:
            problems.append(
                f"{path}: size mismatch (manifest {entry['size']}, on disk {artifact.size})"
            )

    if not problems:
        recomputed = hex_be(merkle_root([a.digest for a in sorted(artifacts, key=lambda x: x.path)],
                                        strict=True))
        if recomputed != manifest_doc.get("merkle_root"):
            problems.append(
                "merkle root mismatch\n"
                f"      manifest    {manifest_doc.get('merkle_root')}\n"
                f"      recomputed  {recomputed}"
            )
    return problems


__all__ = [
    "SCHEMA_MANIFEST",
    "ANCHOR_MAGIC",
    "PRODUCER",
    "Manifest",
    "SignedManifest",
    "build",
    "verify_integrity",
]
