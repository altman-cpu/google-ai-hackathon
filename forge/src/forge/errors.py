"""Error taxonomy for the forge pipeline.

Every failure mode in the pipeline maps to exactly one of these classes. The CLI
maps each class to a distinct process exit code so callers can branch on the
*category* of failure without parsing messages.
"""

from __future__ import annotations


class ForgeError(Exception):
    """Base class for every error raised by forge."""

    exit_code = 1


class ConfigError(ForgeError):
    """Configuration is missing, malformed, or forbidden by a guardrail."""

    exit_code = 78  # EX_CONFIG


class IntentError(ForgeError):
    """The intent document is malformed or semantically invalid."""

    exit_code = 65  # EX_DATAERR


class DesignError(ForgeError):
    """The intent could not be resolved into a build plan."""

    exit_code = 65


class GeneratorError(ForgeError):
    """A generator failed to emit artifacts."""

    exit_code = 70  # EX_SOFTWARE


class IntegrityError(ForgeError):
    """A digest, merkle root, or signature did not verify."""

    exit_code = 66  # EX_NOINPUT -- reused: "the input cannot be trusted"


class SigningError(ForgeError):
    """Signing was requested but could not be performed."""

    exit_code = 77  # EX_NOPERM


class PaymentError(ForgeError):
    """A payment could not be quoted, located, or verified."""

    exit_code = 75  # EX_TEMPFAIL


class NetworkError(ForgeError):
    """An outbound RPC call failed."""

    exit_code = 69  # EX_UNAVAILABLE


class PolicyError(ForgeError):
    """A rigor-level policy gate rejected the operation."""

    exit_code = 77


__all__ = [
    "ForgeError",
    "ConfigError",
    "IntentError",
    "DesignError",
    "GeneratorError",
    "IntegrityError",
    "SigningError",
    "PaymentError",
    "NetworkError",
    "PolicyError",
]
