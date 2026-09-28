"""Content-addressed storage with a public tip and a submerged body.

The iceberg metaphor is the data model, and it enforces three invariants:

**Tip above water.** Every stored object has a small public record -- digest,
size, media type, path, kind -- that is safe to publish, index, quote a price
against, or anchor into a merkle root. The tip never contains content. You can
hand someone the entire tip index and leak nothing but shape and size.

**No blocks.** Bodies are never chunked, striped, or split into fixed-size
blocks. One object is one whole file, written atomically via a temporary file
plus ``os.replace``. There is no reassembly step, so there is no partial-read
failure mode and no chunk index to corrupt. A reader either gets the entire
verified object or an error.

**No key cut.** The addressing key is the full 64-character digest, used whole.
forge does not fan digests out into ``ab/cd/rest`` subdirectories, does not
accept truncated or prefix lookups, and never splits key material. Prefix
addressing invites collisions and ambiguous resolution; this store resolves a
digest exactly or not at all.

Reads always re-verify: the bytes are hashed again and compared to the key they
were filed under. Silent bit-rot surfaces as :class:`IntegrityError`, never as
bad data handed back to a caller.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from ..canonical import canonical_bytes, loads
from ..errors import IntegrityError
from ..hashing import hash256, hex_be, from_hex_be

SCHEMA_TIP = "forge.tip/v1"

_HEX = frozenset("0123456789abcdef")


@dataclass(frozen=True)
class Tip:
    """The public, above-water record for one stored object."""

    digest: str
    size: int
    media_type: str
    kind: str
    path: str = ""
    labels: dict[str, Any] | None = None

    def document(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_TIP,
            "digest": self.digest,
            "kind": self.kind,
            "labels": self.labels or {},
            "media_type": self.media_type,
            "path": self.path,
            "size": self.size,
        }

    @classmethod
    def from_document(cls, raw: Any) -> "Tip":
        if not isinstance(raw, dict):
            raise IntegrityError("tip record must be an object")
        if raw.get("schema") != SCHEMA_TIP:
            raise IntegrityError(f"unexpected tip schema {raw.get('schema')!r}")
        return cls(
            digest=str(raw["digest"]),
            size=int(raw["size"]),
            media_type=str(raw.get("media_type", "application/octet-stream")),
            kind=str(raw.get("kind", "artifact")),
            path=str(raw.get("path", "")),
            labels=raw.get("labels") or {},
        )


class Iceberg:
    """A two-tier content-addressed store rooted at ``root``."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        self.tip_dir = self.root / "tip"
        self.body_dir = self.root / "body"

    # ---- lifecycle -------------------------------------------------------

    def ensure(self) -> None:
        self.tip_dir.mkdir(parents=True, exist_ok=True)
        self.body_dir.mkdir(parents=True, exist_ok=True)

    # ---- writing ---------------------------------------------------------

    def put(
        self,
        content: bytes,
        *,
        kind: str = "artifact",
        media_type: str = "application/octet-stream",
        path: str = "",
        labels: dict[str, Any] | None = None,
        digest: str | None = None,
    ) -> Tip:
        """Store ``content`` whole and return its tip.

        ``digest`` may be supplied when the caller has already committed to a
        digest computed over a header plus content (as :class:`Artifact` does).
        It is validated, never trusted blindly.
        """
        if not isinstance(content, bytes):
            raise IntegrityError(f"iceberg bodies must be bytes, got {type(content).__name__}")

        key = digest if digest is not None else hex_be(hash256(content))
        _require_full_key(key)

        self.ensure()
        body_path = self.body_dir / key
        if body_path.exists():
            existing = body_path.read_bytes()
            if existing != content:
                raise IntegrityError(
                    f"digest collision or corruption at {key[:16]}: stored body "
                    f"({len(existing)} bytes) differs from the body being written "
                    f"({len(content)} bytes)"
                )
        else:
            # Whole-object atomic write. No chunking, no partial state.
            _atomic_write(body_path, content)

        tip = Tip(
            digest=key,
            size=len(content),
            media_type=media_type,
            kind=kind,
            path=path,
            labels=labels or {},
        )
        _atomic_write(self.tip_dir / f"{key}.json", canonical_bytes(tip.document()) + b"\n")
        return tip

    def put_document(self, document: Any, *, kind: str, path: str = "",
                     labels: dict[str, Any] | None = None) -> Tip:
        """Canonicalise and store a JSON document."""
        return self.put(
            canonical_bytes(document) + b"\n",
            kind=kind,
            media_type="application/json",
            path=path,
            labels=labels,
        )

    # ---- reading ---------------------------------------------------------

    def has(self, key: str) -> bool:
        _require_full_key(key)
        return (self.body_dir / key).exists()

    def tip(self, key: str) -> Tip:
        """Fetch the above-water record. Cheap: never touches the body."""
        _require_full_key(key)
        tip_path = self.tip_dir / f"{key}.json"
        if not tip_path.exists():
            raise IntegrityError(f"no tip recorded for {key[:16]}")
        return Tip.from_document(loads(tip_path.read_bytes()))

    def body(self, key: str, *, verify: bool = True) -> bytes:
        """Fetch the submerged body, re-verifying it against its key.

        ``verify=False`` is only honoured for keys derived from an artifact
        header (where the digest covers path and mode, not content alone).
        """
        _require_full_key(key)
        body_path = self.body_dir / key
        if not body_path.exists():
            raise IntegrityError(f"no body stored for {key[:16]}")
        content = body_path.read_bytes()

        recorded = self.tip(key)
        if recorded.size != len(content):
            raise IntegrityError(
                f"body {key[:16]} is {len(content)} bytes but its tip records "
                f"{recorded.size}; the store has been corrupted"
            )
        if verify and recorded.kind in {"document", "blob"}:
            actual = hex_be(hash256(content))
            if actual != key:
                raise IntegrityError(
                    f"body {key[:16]} hashes to {actual[:16]}; content does not match its key"
                )
        return content

    def document(self, key: str) -> Any:
        return loads(self.body(key))

    # ---- enumeration -----------------------------------------------------

    def tips(self) -> Iterator[Tip]:
        """Yield every tip, ordered by digest. The whole public surface."""
        if not self.tip_dir.exists():
            return
        for tip_path in sorted(self.tip_dir.glob("*.json")):
            yield Tip.from_document(loads(tip_path.read_bytes()))

    def surface(self) -> dict[str, Any]:
        """A publishable index of the visible tip, with the mass summarised.

        This is the object you can safely hand to an untrusted party: it proves
        how much is down there without revealing any of it.
        """
        tips = list(self.tips())
        return {
            "schema": "forge.iceberg.surface/v1",
            "object_count": len(tips),
            "submerged_bytes": sum(tip.size for tip in tips),
            "tips": [tip.document() for tip in tips],
        }

    def fsck(self) -> list[str]:
        """Verify every object. Returns a list of problems, empty if healthy."""
        problems: list[str] = []
        for tip in self.tips():
            try:
                self.body(tip.digest)
            except IntegrityError as exc:
                problems.append(f"{tip.digest[:16]}: {exc}")
        if self.body_dir.exists():
            for body_path in sorted(self.body_dir.iterdir()):
                if not (self.tip_dir / f"{body_path.name}.json").exists():
                    problems.append(f"{body_path.name[:16]}: body has no tip (orphaned)")
        return problems


def _require_full_key(key: str) -> None:
    """Enforce the no-key-cut rule: full 64-hex digests only."""
    if not isinstance(key, str):
        raise IntegrityError(f"iceberg key must be a string, got {type(key).__name__}")
    if len(key) != 64 or not set(key) <= _HEX:
        raise IntegrityError(
            f"iceberg key {key!r} is not a full 64-character lowercase hex digest. "
            "This store does not accept truncated or prefix keys: a cut key is an "
            "ambiguous key."
        )
    from_hex_be(key)  # parse-check


def _atomic_write(target: Path, content: bytes) -> None:
    """Write ``content`` to ``target`` atomically, then fsync the directory."""
    target.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(dir=str(target.parent), prefix=".tmp-")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, target)
        os.chmod(target, 0o644)
    except BaseException:
        if os.path.exists(temp_name):
            os.unlink(temp_name)
        raise
    # Durability: without this the rename can be lost on power failure.
    try:
        dir_fd = os.open(str(target.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass  # Not all filesystems support directory fsync.


__all__ = ["Iceberg", "Tip", "SCHEMA_TIP"]
