"""Detached OpenPGP signatures, via the system ``gpg`` binary.

forge does not implement OpenPGP. It shells out to GnuPG, because a hand-rolled
signature implementation is exactly the kind of thing that looks fine in a demo
and is catastrophic in production. GnuPG owns the keyring, the agent, the
pinentry, and the smartcard path; forge only hands it bytes.

Key material never passes through forge. There is no key argument that accepts
a secret, no passphrase parameter, no key import path. The operator names a key
by id or fingerprint (``FORGE_GPG_KEY``) and gpg-agent does the rest. Nothing
secret is logged, persisted, or included in any digest.

When ``gpg`` is unavailable, signing fails loudly rather than emitting an
unsigned artifact that looks signed. At ``extreme`` rigor this stops the build.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass

from ..errors import SigningError

# gpg's --status-fd vocabulary that we care about.
_STATUS_GOOD = "GOODSIG"
_STATUS_VALID = "VALIDSIG"
_STATUS_BAD = "BADSIG"
_STATUS_EXPIRED = "EXPKEYSIG"
_STATUS_REVOKED = "REVKEYSIG"
_STATUS_NO_KEY = "NO_PUBKEY"
_STATUS_ERRSIG = "ERRSIG"


@dataclass(frozen=True)
class Signature:
    """An armoured detached signature plus the key that made it."""

    armored: str
    key_id: str

    def document(self) -> dict[str, object]:
        return {"armored": self.armored, "key_id": self.key_id, "kind": "openpgp-detached"}


@dataclass(frozen=True)
class Verification:
    """Outcome of verifying a detached signature."""

    valid: bool
    status: str
    fingerprint: str = ""
    signer: str = ""
    detail: str = ""

    def document(self) -> dict[str, object]:
        return {
            "detail": self.detail,
            "fingerprint": self.fingerprint,
            "signer": self.signer,
            "status": self.status,
            "valid": self.valid,
        }


def is_available(binary: str = "gpg") -> bool:
    """True when the gpg binary can be located and executed."""
    return shutil.which(binary) is not None


def version(binary: str = "gpg") -> str:
    if not is_available(binary):
        return ""
    try:
        result = _run([binary, "--version"], b"")
    except SigningError:
        return ""
    first = result.stdout.decode("utf-8", "replace").splitlines()
    return first[0].strip() if first else ""


def sign_detached(data: bytes, key_id: str | None = None, binary: str = "gpg") -> Signature:
    """Produce an ASCII-armoured detached signature over ``data``."""
    if not is_available(binary):
        raise SigningError(
            f"{binary!r} was not found on PATH, so the manifest cannot be signed.\n"
            "  Install GnuPG and set FORGE_GPG_KEY to a key id, or drop rigor below "
            "'extreme' to build without a signature."
        )

    argv = [
        binary,
        "--batch",
        "--yes",
        "--armor",
        "--detach-sign",
        "--digest-algo", "SHA256",   # match the hash family used everywhere else
        "--status-fd", "2",
    ]
    if key_id:
        argv += ["--local-user", key_id]
    argv += ["--output", "-", "-"]

    result = _run(argv, data)
    if result.returncode != 0:
        raise SigningError(
            f"gpg exited {result.returncode} while signing:\n"
            + _indent(result.stderr.decode("utf-8", "replace"))
            + "\n  If this says 'No secret key', set FORGE_GPG_KEY to a key you hold."
        )

    armored = result.stdout.decode("utf-8", "replace").strip()
    if "BEGIN PGP SIGNATURE" not in armored:
        raise SigningError("gpg produced no armoured signature block")
    return Signature(armored=armored + "\n", key_id=key_id or _signer_from_status(result.stderr))


def verify_detached(data: bytes, armored: str, binary: str = "gpg") -> Verification:
    """Verify an armoured detached signature over ``data``.

    A signature that is cryptographically valid but made by an unknown key is
    reported as ``valid=False`` with status ``NO_PUBKEY``. "The maths checks
    out" is not the same as "I trust this", and conflating them is how signature
    checks become decorative.
    """
    if not is_available(binary):
        return Verification(
            valid=False,
            status="UNAVAILABLE",
            detail=f"{binary!r} is not installed, so the signature cannot be checked",
        )

    with tempfile.TemporaryDirectory(prefix="forge-verify-") as scratch:
        sig_path = os.path.join(scratch, "manifest.asc")
        data_path = os.path.join(scratch, "manifest.json")
        with open(sig_path, "w", encoding="utf-8") as handle:
            handle.write(armored)
        with open(data_path, "wb") as handle:
            handle.write(data)

        result = _run(
            [binary, "--batch", "--status-fd", "1", "--verify", sig_path, data_path],
            b"",
        )

    status_text = result.stdout.decode("utf-8", "replace")
    stderr_text = result.stderr.decode("utf-8", "replace")
    fingerprint = ""
    signer = ""
    status = "UNKNOWN"
    valid = False

    for line in status_text.splitlines():
        if not line.startswith("[GNUPG:] "):
            continue
        parts = line[len("[GNUPG:] "):].split(" ")
        code = parts[0]
        if code == _STATUS_GOOD:
            status = "GOOD"
            if len(parts) > 2:
                signer = " ".join(parts[2:])
        elif code == _STATUS_VALID and len(parts) > 1:
            fingerprint = parts[1]
            valid = True
        elif code == _STATUS_BAD:
            status = "BAD"
            valid = False
            break
        elif code == _STATUS_EXPIRED:
            status = "EXPIRED_KEY"
        elif code == _STATUS_REVOKED:
            status = "REVOKED_KEY"
            valid = False
        elif code == _STATUS_NO_KEY:
            status = "NO_PUBKEY"
            valid = False
        elif code == _STATUS_ERRSIG:
            status = "ERROR"
            valid = False

    # An expired or revoked key still produces VALIDSIG; refuse both.
    if status in {"EXPIRED_KEY", "REVOKED_KEY", "NO_PUBKEY", "BAD", "ERROR"}:
        valid = False

    return Verification(
        valid=valid,
        status=status,
        fingerprint=fingerprint,
        signer=signer,
        detail=stderr_text.strip().splitlines()[-1] if stderr_text.strip() else "",
    )


def _signer_from_status(stderr: bytes) -> str:
    for line in stderr.decode("utf-8", "replace").splitlines():
        if line.startswith("[GNUPG:] SIG_CREATED"):
            parts = line.split(" ")
            if len(parts) > 3:
                return parts[-1]
    return ""


def _run(argv: list[str], stdin: bytes) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            argv,
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
        )
    except FileNotFoundError as exc:
        raise SigningError(f"could not execute {argv[0]!r}: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise SigningError(
            f"{argv[0]} timed out after 120s; a pinentry prompt may be waiting for input. "
            "Use a key with no passphrase or a preloaded gpg-agent for unattended builds."
        ) from exc


def _indent(text: str, prefix: str = "    ") -> str:
    return "\n".join(prefix + line for line in text.strip().splitlines())


__all__ = ["Signature", "Verification", "is_available", "version", "sign_detached", "verify_detached"]
