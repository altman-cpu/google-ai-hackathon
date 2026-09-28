"""Runtime configuration, rigor levels, and network guardrails.

Everything is resolved from environment variables so the same artifact runs
identically under a shell, a container, and the NixOS module in ``nix/``.
No secret is ever read from, or written to, a file inside the repository.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .errors import ConfigError

# 1 SEI = 1_000_000 usei, the on-chain base denomination.
USEI_PER_SEI = 1_000_000


class Rigor(str, Enum):
    """How hard the pipeline fails.

    Each level is a strict superset of the previous one.

    ``lax``       -- generate, warn about everything, gate nothing.
    ``standard``  -- validation errors fail the build; warnings are printed.
    ``strict``    -- warnings become errors; artifacts must be digest-stable
                     across two independent runs.
    ``extreme``   -- everything in ``strict``, plus: a PGP signature is
                     mandatory, the merkle root must be reproducible, payment
                     must be settled before artifacts are written to disk, and
                     the LLM designer is forbidden from introducing any node
                     that the intent did not declare.
    """

    LAX = "lax"
    STANDARD = "standard"
    STRICT = "strict"
    EXTREME = "extreme"

    @property
    def rank(self) -> int:
        return {"lax": 0, "standard": 1, "strict": 2, "extreme": 3}[self.value]

    def at_least(self, other: "Rigor") -> bool:
        return self.rank >= other.rank

    @property
    def warnings_are_errors(self) -> bool:
        return self.at_least(Rigor.STRICT)

    @property
    def requires_signature(self) -> bool:
        return self.at_least(Rigor.EXTREME)

    @property
    def requires_settled_payment(self) -> bool:
        return self.at_least(Rigor.EXTREME)

    @property
    def requires_reproducibility_check(self) -> bool:
        return self.at_least(Rigor.STRICT)


@dataclass(frozen=True)
class SeiNetwork:
    """A SEI network endpoint set.

    ``lcd`` is the Cosmos SDK REST gateway, ``evm_rpc`` the Ethereum-compatible
    JSON-RPC endpoint. SEI exposes both over the same underlying chain, so a
    payment may be verified through either surface.
    """

    name: str
    chain_id: str
    lcd: str
    evm_rpc: str
    evm_chain_id: int
    is_mainnet: bool
    explorer: str

    @property
    def requires_opt_in(self) -> bool:
        return self.is_mainnet


# Public endpoints. Operators should override these with their own providers;
# public RPC is rate-limited and must not be trusted for settlement finality.
NETWORKS: dict[str, SeiNetwork] = {
    "pacific-1": SeiNetwork(
        name="pacific-1",
        chain_id="pacific-1",
        lcd="https://rest.sei-apis.com",
        evm_rpc="https://evm-rpc.sei-apis.com",
        evm_chain_id=1329,
        is_mainnet=True,
        explorer="https://seitrace.com",
    ),
    "atlantic-2": SeiNetwork(
        name="atlantic-2",
        chain_id="atlantic-2",
        lcd="https://rest-testnet.sei-apis.com",
        evm_rpc="https://evm-rpc-testnet.sei-apis.com",
        evm_chain_id=1328,
        is_mainnet=False,
        explorer="https://seitrace.com/?chain=atlantic-2",
    ),
    "arctic-1": SeiNetwork(
        name="arctic-1",
        chain_id="arctic-1",
        lcd="https://rest-arctic-1.sei-apis.com",
        evm_rpc="https://evm-rpc-arctic-1.sei-apis.com",
        evm_chain_id=713715,
        is_mainnet=False,
        explorer="https://seitrace.com/?chain=arctic-1",
    ),
}

DEFAULT_NETWORK = "atlantic-2"  # testnet by default, always


@dataclass(frozen=True)
class Config:
    """Fully resolved runtime configuration."""

    rigor: Rigor = Rigor.STANDARD
    workdir: Path = field(default_factory=lambda: Path(".forge"))
    network: SeiNetwork = field(default_factory=lambda: NETWORKS[DEFAULT_NETWORK])
    allow_mainnet: bool = False
    payee: str | None = None
    min_confirmations: int = 1
    gpg_key: str | None = None
    gpg_binary: str = "gpg"
    gemini_api_key: str | None = None
    gemini_model: str = "gemini-1.5-pro"
    source_date_epoch: int = 0
    http_timeout: int = 20

    @property
    def iceberg_dir(self) -> Path:
        return self.workdir / "iceberg"

    @property
    def out_dir(self) -> Path:
        return self.workdir / "out"

    def require_mainnet_opt_in(self) -> None:
        """Refuse to touch mainnet unless the operator explicitly opted in.

        Selecting a mainnet endpoint is not sufficient. ``FORGE_ALLOW_MAINNET=1``
        must also be set, so no default, typo, or copied command can move real
        value by accident.
        """
        if self.network.is_mainnet and not self.allow_mainnet:
            raise ConfigError(
                f"network {self.network.name!r} is MAINNET and involves real funds.\n"
                "  Set FORGE_ALLOW_MAINNET=1 to proceed, or pass --network atlantic-2 "
                "to use testnet.\n"
                "  forge never holds private keys: it issues payment requests and "
                "verifies settlement read-only."
            )


def load(overrides: dict[str, object] | None = None) -> Config:
    """Resolve configuration from the environment, then apply ``overrides``."""
    env = os.environ
    overrides = dict(overrides or {})

    network_name = str(overrides.pop("network", None) or env.get("FORGE_SEI_NETWORK") or DEFAULT_NETWORK)
    if network_name not in NETWORKS:
        raise ConfigError(
            f"unknown SEI network {network_name!r}; known networks: {', '.join(sorted(NETWORKS))}"
        )
    network = NETWORKS[network_name]

    # Endpoint overrides let an operator point at their own node.
    lcd = env.get("FORGE_SEI_LCD")
    evm_rpc = env.get("FORGE_SEI_EVM_RPC")
    if lcd or evm_rpc:
        network = SeiNetwork(
            name=network.name,
            chain_id=network.chain_id,
            lcd=lcd or network.lcd,
            evm_rpc=evm_rpc or network.evm_rpc,
            evm_chain_id=network.evm_chain_id,
            is_mainnet=network.is_mainnet,
            explorer=network.explorer,
        )

    rigor_raw = str(overrides.pop("rigor", None) or env.get("FORGE_RIGOR") or Rigor.STANDARD.value)
    try:
        rigor = Rigor(rigor_raw.lower())
    except ValueError as exc:
        raise ConfigError(
            f"unknown rigor {rigor_raw!r}; choose one of: "
            + ", ".join(level.value for level in Rigor)
        ) from exc

    workdir = Path(str(overrides.pop("workdir", None) or env.get("FORGE_WORKDIR") or ".forge"))

    config = Config(
        rigor=rigor,
        workdir=workdir,
        network=network,
        allow_mainnet=_flag(env.get("FORGE_ALLOW_MAINNET")),
        payee=overrides.pop("payee", None) or env.get("FORGE_SEI_PAYEE") or None,
        min_confirmations=_int(env.get("FORGE_MIN_CONFIRMATIONS"), 1, "FORGE_MIN_CONFIRMATIONS"),
        gpg_key=overrides.pop("gpg_key", None) or env.get("FORGE_GPG_KEY") or None,
        gpg_binary=env.get("FORGE_GPG_BINARY") or "gpg",
        # Read but never logged, never persisted, never included in a digest.
        gemini_api_key=env.get("GEMINI_API_KEY") or env.get("FORGE_GEMINI_API_KEY") or None,
        gemini_model=env.get("FORGE_GEMINI_MODEL") or "gemini-1.5-pro",
        # SOURCE_DATE_EPOCH is the reproducible-builds standard. Defaulting to 0
        # keeps output byte-identical across runs unless explicitly overridden.
        source_date_epoch=_int(env.get("SOURCE_DATE_EPOCH"), 0, "SOURCE_DATE_EPOCH"),
        http_timeout=_int(env.get("FORGE_HTTP_TIMEOUT"), 20, "FORGE_HTTP_TIMEOUT"),
    )

    for key, value in overrides.items():
        if value is not None:
            raise ConfigError(f"unknown configuration override {key!r}")
    return config


def _flag(raw: str | None) -> bool:
    return (raw or "").strip().lower() in {"1", "true", "yes", "on"}


def _int(raw: str | None, default: int, label: str) -> int:
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{label} must be an integer, got {raw!r}") from exc
    if value < 0:
        raise ConfigError(f"{label} must be non-negative, got {value}")
    return value


__all__ = [
    "USEI_PER_SEI",
    "Rigor",
    "SeiNetwork",
    "NETWORKS",
    "DEFAULT_NETWORK",
    "Config",
    "load",
]
