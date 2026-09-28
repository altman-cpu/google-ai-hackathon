"""Transform objects: the unit of work, provenance, and commitment.

A ``TransformObject`` is an immutable, content-addressed record of one
transformation:

    inputs + operation + parameters  ->  outputs

Transform objects chain. Each one names its parents by digest, so a completed
build is a directed acyclic graph whose root digest commits to every input,
every parameter, and every byte of output that produced it. Change a single
character of an intent document and every downstream digest changes.

Two properties are load-bearing:

* **Deterministic.** No wall-clock reads, no PRNG, no dict iteration order, no
  absolute paths. The timestamp comes from ``SOURCE_DATE_EPOCH``. Running the
  same build twice on different machines yields the same root digest.
* **Self-describing.** The digest covers the ``schema`` field, so a future
  format change cannot collide with an existing digest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from .errors import IntegrityError
from .hashing import digest_object, hash256, hex_be, merkle_root

SCHEMA_ARTIFACT = "forge.artifact/v1"
SCHEMA_TRANSFORM = "forge.transform/v1"


@dataclass(frozen=True)
class Artifact:
    """A single emitted file, committed by content.

    ``path`` is always repository-relative with forward slashes. Absolute paths
    and ``..`` traversal are rejected, both because they break reproducibility
    and because a generator must never be able to write outside the output root.
    """

    path: str
    content: bytes
    mode: int = 0o644
    media_type: str = "text/plain"

    def __post_init__(self) -> None:
        if not self.path or self.path.strip() != self.path:
            raise IntegrityError(f"artifact path {self.path!r} is empty or has stray whitespace")
        if self.path.startswith("/") or self.path.startswith("~"):
            raise IntegrityError(f"artifact path {self.path!r} must be relative")
        if "\\" in self.path:
            raise IntegrityError(f"artifact path {self.path!r} must use forward slashes")
        parts = self.path.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            raise IntegrityError(f"artifact path {self.path!r} contains a traversal segment")
        if not isinstance(self.content, bytes):
            raise IntegrityError(f"artifact {self.path!r} content must be bytes")
        if self.mode not in (0o644, 0o755):
            raise IntegrityError(f"artifact {self.path!r} mode must be 0644 or 0755")

    @property
    def digest(self) -> bytes:
        """``hash256`` over a header plus the content.

        The header binds the path and mode into the digest, so moving a file or
        flipping its executable bit changes its identity. Length-prefixing the
        path prevents a ``path||content`` concatenation ambiguity.
        """
        header = b"forge.artifact\x00%d\x00%o\x00%s\x00" % (
            len(self.path.encode("utf-8")),
            self.mode,
            self.path.encode("utf-8"),
        )
        return hash256(header + self.content)

    @property
    def digest_hex(self) -> str:
        return hex_be(self.digest)

    @property
    def size(self) -> int:
        return len(self.content)

    def tip(self) -> dict[str, Any]:
        """The public, above-water record: metadata only, never content."""
        return {
            "schema": SCHEMA_ARTIFACT,
            "digest": self.digest_hex,
            "media_type": self.media_type,
            "mode": f"{self.mode:04o}",
            "path": self.path,
            "size": self.size,
        }


@dataclass(frozen=True)
class TransformObject:
    """One node in the provenance DAG."""

    operation: str
    inputs: tuple[str, ...] = ()
    params: dict[str, Any] = field(default_factory=dict)
    outputs: tuple[Artifact, ...] = ()
    parents: tuple[str, ...] = ()
    timestamp: int = 0
    rigor: str = "standard"

    def __post_init__(self) -> None:
        if not self.operation:
            raise IntegrityError("transform operation must be a non-empty string")
        paths = [artifact.path for artifact in self.outputs]
        duplicates = sorted({path for path in paths if paths.count(path) > 1})
        if duplicates:
            raise IntegrityError(
                "transform emits the same path more than once: " + ", ".join(duplicates)
            )

    @property
    def outputs_root(self) -> bytes:
        """Merkle root over output artifacts, ordered by path.

        Sorting by path rather than emission order means a generator that
        reorders its internal loops does not change the commitment.
        """
        leaves = [artifact.digest for artifact in sorted(self.outputs, key=lambda a: a.path)]
        return merkle_root(leaves, strict=True)

    def body(self) -> dict[str, Any]:
        """The canonical document that gets hashed. Order-independent by design."""
        return {
            "schema": SCHEMA_TRANSFORM,
            "inputs": sorted(self.inputs),
            "operation": self.operation,
            "outputs": [artifact.tip() for artifact in sorted(self.outputs, key=lambda a: a.path)],
            "outputs_root": hex_be(self.outputs_root),
            "params": self.params,
            "parents": sorted(self.parents),
            "rigor": self.rigor,
            "timestamp": self.timestamp,
        }

    @property
    def digest(self) -> bytes:
        return digest_object(self.body())

    @property
    def digest_hex(self) -> str:
        return hex_be(self.digest)

    def tip(self) -> dict[str, Any]:
        """Above-water summary of this transform."""
        return {
            "schema": SCHEMA_TRANSFORM,
            "digest": self.digest_hex,
            "operation": self.operation,
            "output_count": len(self.outputs),
            "outputs_root": hex_be(self.outputs_root),
            "parents": sorted(self.parents),
            "total_bytes": sum(artifact.size for artifact in self.outputs),
        }

    def with_parents(self, parents: Iterable[str]) -> "TransformObject":
        """Return a copy chained onto ``parents``. Transforms are immutable."""
        return TransformObject(
            operation=self.operation,
            inputs=self.inputs,
            params=self.params,
            outputs=self.outputs,
            parents=tuple(sorted(parents)),
            timestamp=self.timestamp,
            rigor=self.rigor,
        )


@dataclass(frozen=True)
class TransformChain:
    """An ordered DAG of transforms plus its aggregate commitment."""

    transforms: tuple[TransformObject, ...]

    @property
    def root(self) -> bytes:
        """Merkle root over transform digests, in declaration order.

        Order is preserved here (unlike artifacts, which sort by path) because
        the sequence of transforms is itself meaningful: it is the build order.
        """
        return merkle_root([t.digest for t in self.transforms], strict=True)

    @property
    def root_hex(self) -> str:
        return hex_be(self.root)

    @property
    def artifacts(self) -> list[Artifact]:
        collected: list[Artifact] = []
        for transform in self.transforms:
            collected.extend(transform.outputs)
        return sorted(collected, key=lambda a: a.path)

    def verify_links(self) -> None:
        """Assert every declared parent exists and precedes its child."""
        seen: set[str] = set()
        for transform in self.transforms:
            for parent in transform.parents:
                if parent not in seen:
                    raise IntegrityError(
                        f"transform {transform.digest_hex[:16]} ({transform.operation}) "
                        f"names parent {parent[:16]} which does not precede it in the chain"
                    )
            seen.add(transform.digest_hex)

    def document(self) -> dict[str, Any]:
        return {
            "schema": "forge.chain/v1",
            "root": self.root_hex,
            "transforms": [transform.body() for transform in self.transforms],
        }


def collect_artifacts(transforms: Sequence[TransformObject]) -> list[Artifact]:
    """Flatten artifacts across transforms, rejecting cross-transform collisions."""
    by_path: dict[str, Artifact] = {}
    for transform in transforms:
        for artifact in transform.outputs:
            existing = by_path.get(artifact.path)
            if existing is not None and existing.digest != artifact.digest:
                raise IntegrityError(
                    f"two transforms emit conflicting content for {artifact.path!r}"
                )
            by_path[artifact.path] = artifact
    return [by_path[path] for path in sorted(by_path)]


__all__ = [
    "SCHEMA_ARTIFACT",
    "SCHEMA_TRANSFORM",
    "Artifact",
    "TransformObject",
    "TransformChain",
    "collect_artifacts",
]
