"""Read-only SEI chain client.

**This module cannot spend money.** It has no signing code, no key handling, no
transaction construction, and no broadcast path. Every method is a GET or a
read-only JSON-RPC query. The worst a bug here can do is report a payment as
unsettled when it settled, which fails safe.

SEI exposes the same chain through two surfaces, and a payment may arrive over
either:

* **Cosmos LCD** -- REST, for ``bank`` transfers between ``sei1...`` addresses
* **EVM JSON-RPC** -- for native transfers between ``0x...`` addresses

Both are queried here, so a payer can use whichever wallet they already have.

Finality note: SEI has fast finality, but a public RPC endpoint can still serve
a stale or forked view. Operators settling real value should point
``FORGE_SEI_LCD`` / ``FORGE_SEI_EVM_RPC`` at their own node and require several
confirmations via ``FORGE_MIN_CONFIRMATIONS``.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from ..config import SeiNetwork
from ..errors import NetworkError, PaymentError

USER_AGENT = "forge/0.1.0 (+read-only chain queries)"


@dataclass(frozen=True)
class Transfer:
    """A native SEI transfer discovered on chain."""

    tx_hash: str
    recipient: str
    sender: str
    amount_usei: int
    denom: str
    memo: str
    height: int
    succeeded: bool
    surface: str  # "cosmos" | "evm"

    def document(self) -> dict[str, Any]:
        return {
            "amount_usei": self.amount_usei,
            "denom": self.denom,
            "height": self.height,
            "memo": self.memo,
            "recipient": self.recipient,
            "sender": self.sender,
            "succeeded": self.succeeded,
            "surface": self.surface,
            "tx_hash": self.tx_hash,
        }


class SeiClient:
    """Read-only access to a SEI network."""

    def __init__(self, network: SeiNetwork, *, timeout: int = 20) -> None:
        self.network = network
        self.timeout = timeout

    # ---- height ----------------------------------------------------------

    def latest_height(self) -> int:
        """Current chain height, via LCD with an EVM fallback."""
        try:
            payload = self._get(f"{self.network.lcd}/cosmos/base/tendermint/v1beta1/blocks/latest")
            return int(payload["block"]["header"]["height"])
        except (NetworkError, KeyError, ValueError, TypeError):
            result = self._rpc("eth_blockNumber", [])
            return int(str(result), 16)

    # ---- transaction lookup ---------------------------------------------

    def find_transfer(self, tx_hash: str) -> Transfer:
        """Locate a native transfer by hash on either surface."""
        cleaned = tx_hash.strip()
        if not cleaned:
            raise PaymentError("transaction hash is empty")

        if cleaned.lower().startswith("0x"):
            return self._evm_transfer(cleaned)

        # Cosmos tx hashes are uppercase hex, 64 characters.
        normalised = cleaned.upper()
        if len(normalised) != 64 or any(c not in "0123456789ABCDEF" for c in normalised):
            raise PaymentError(
                f"{tx_hash!r} is not a SEI transaction hash: expected 64 hex characters "
                "(Cosmos) or a 0x-prefixed 32-byte hash (EVM)"
            )
        return self._cosmos_transfer(normalised)

    def _cosmos_transfer(self, tx_hash: str) -> Transfer:
        url = f"{self.network.lcd}/cosmos/tx/v1beta1/txs/{tx_hash}"
        try:
            payload = self._get(url)
        except NetworkError as exc:
            if "404" in str(exc):
                raise PaymentError(
                    f"transaction {tx_hash[:16]}... was not found on {self.network.name}. "
                    "It may be unconfirmed, or on a different network."
                ) from exc
            raise

        response = payload.get("tx_response") or {}
        tx_body = ((payload.get("tx") or {}).get("body")) or {}
        code = int(response.get("code", 0) or 0)
        height = int(response.get("height", 0) or 0)
        memo = str(tx_body.get("memo", "") or "")

        recipient = sender = ""
        amount = 0
        denom = ""
        for message in tx_body.get("messages", []) or []:
            if not isinstance(message, dict):
                continue
            if message.get("@type") != "/cosmos.bank.v1beta1.MsgSend":
                continue
            sender = str(message.get("from_address", ""))
            recipient = str(message.get("to_address", ""))
            for coin in message.get("amount", []) or []:
                if coin.get("denom") == "usei":
                    amount += int(coin.get("amount", 0))
                    denom = "usei"
            break

        if not recipient:
            raise PaymentError(
                f"transaction {tx_hash[:16]}... contains no /cosmos.bank.v1beta1.MsgSend "
                "transfer; forge only recognises native usei transfers"
            )

        return Transfer(
            tx_hash=tx_hash,
            recipient=recipient,
            sender=sender,
            amount_usei=amount,
            denom=denom or "usei",
            memo=memo,
            height=height,
            succeeded=(code == 0),
            surface="cosmos",
        )

    def _evm_transfer(self, tx_hash: str) -> Transfer:
        tx = self._rpc("eth_getTransactionByHash", [tx_hash])
        if tx is None:
            raise PaymentError(
                f"transaction {tx_hash[:18]}... was not found on {self.network.name} "
                "via the EVM surface"
            )
        receipt = self._rpc("eth_getTransactionReceipt", [tx_hash]) or {}

        block_number = tx.get("blockNumber")
        height = int(str(block_number), 16) if block_number else 0
        # EVM value is wei-scaled (18 dp). SEI's usei is 6 dp, so 10**12 wei = 1 usei.
        value_wei = int(str(tx.get("value", "0x0")), 16)
        amount_usei = value_wei // 10**12
        status = receipt.get("status")
        succeeded = (int(str(status), 16) == 1) if status is not None else bool(height)

        # EVM transactions carry no memo field. The payer encodes the invoice
        # reference in calldata instead; we surface it as the memo.
        memo = _decode_calldata_memo(str(tx.get("input", "0x")))

        return Transfer(
            tx_hash=tx_hash,
            recipient=str(tx.get("to") or ""),
            sender=str(tx.get("from") or ""),
            amount_usei=amount_usei,
            denom="usei",
            memo=memo,
            height=height,
            succeeded=succeeded,
            surface="evm",
        )

    # ---- transport -------------------------------------------------------

    def _get(self, url: str) -> dict[str, Any]:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                                       "Accept": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise NetworkError(f"GET {url} failed: HTTP {exc.code} {exc.reason}") from exc
        except urllib.error.URLError as exc:
            raise NetworkError(f"GET {url} failed: {exc.reason}") from exc
        except json.JSONDecodeError as exc:
            raise NetworkError(f"GET {url} returned malformed JSON: {exc}") from exc

    def _rpc(self, method: str, params: list[Any]) -> Any:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        request = urllib.request.Request(
            self.network.evm_rpc,
            data=body.encode("utf-8"),
            headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise NetworkError(f"{method} failed: HTTP {exc.code} {exc.reason}") from exc
        except urllib.error.URLError as exc:
            raise NetworkError(f"{method} failed: {exc.reason}") from exc
        except json.JSONDecodeError as exc:
            raise NetworkError(f"{method} returned malformed JSON: {exc}") from exc

        if "error" in payload:
            error = payload["error"]
            raise NetworkError(
                f"{method} returned RPC error {error.get('code')}: {error.get('message')}"
            )
        return payload.get("result")


def _decode_calldata_memo(calldata: str) -> str:
    """Interpret EVM calldata as a UTF-8 memo when it plausibly is one."""
    raw = calldata[2:] if calldata.lower().startswith("0x") else calldata
    if not raw:
        return ""
    try:
        decoded = bytes.fromhex(raw)
    except ValueError:
        return ""
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return ""
    return text if text.isprintable() else ""


__all__ = ["SeiClient", "Transfer"]
