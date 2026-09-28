"""Pricing arithmetic, address validation, and the non-custodial gateway."""

from __future__ import annotations

import unittest

from forge.config import USEI_PER_SEI, Config, Rigor
from forge.errors import ConfigError, PaymentError
from forge.payments import address as address_mod
from forge.payments.address import to_checksum_address
from forge.payments.catalog import (
    RIGOR_BASIS_POINTS,
    format_sei,
    parse_sei,
    price_build,
    published_catalog,
)
from forge.payments.gateway import build_request, derive_reference, request_from_document
from forge.payments.keccak import keccak256_hex


def bech32_encode(hrp: str, payload: bytes) -> str:
    """Reference bech32 encoder, used to mint valid test addresses."""
    charset = address_mod.BECH32_CHARSET
    data: list[int] = []
    acc = bits = 0
    for byte in payload:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)
    values = address_mod._bech32_hrp_expand(hrp) + data + [0, 0, 0, 0, 0, 0]
    polymod = address_mod._bech32_polymod(values) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(charset[d] for d in data + checksum)


VALID_SEI = bech32_encode("sei", bytes(range(20)))


class TestKeccak(unittest.TestCase):
    """Published Keccak-256 vectors. These must never drift."""

    def test_empty(self) -> None:
        self.assertEqual(
            keccak256_hex(b""),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )

    def test_abc(self) -> None:
        self.assertEqual(
            keccak256_hex(b"abc"),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        )

    def test_crosses_rate_boundary(self) -> None:
        """Input longer than the 136-byte rate exercises multi-block absorption."""
        self.assertEqual(len(keccak256_hex(b"a" * 200)), 64)

    def test_is_not_sha3(self) -> None:
        import hashlib

        self.assertNotEqual(keccak256_hex(b""), hashlib.sha3_256(b"").hexdigest())


class TestEip55(unittest.TestCase):
    """The four reference addresses from EIP-55 itself."""

    CASES = [
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ]

    def test_checksums_match_spec(self) -> None:
        for expected in self.CASES:
            self.assertEqual(to_checksum_address(expected[2:].lower()), expected)

    def test_accepts_checksummed(self) -> None:
        for candidate in self.CASES:
            self.assertEqual(address_mod.parse(candidate).kind, "evm")

    def test_accepts_all_lowercase(self) -> None:
        parsed = address_mod.parse(self.CASES[0].lower())
        self.assertEqual(parsed.value, self.CASES[0])

    def test_rejects_corrupted_case(self) -> None:
        broken = "0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        with self.assertRaises(PaymentError) as caught:
            address_mod.parse(broken)
        self.assertIn("EIP-55", str(caught.exception))

    def test_rejects_wrong_length(self) -> None:
        with self.assertRaises(PaymentError):
            address_mod.parse("0xdeadbeef")


class TestBech32(unittest.TestCase):
    def test_accepts_valid_sei_address(self) -> None:
        parsed = address_mod.parse(VALID_SEI)
        self.assertEqual(parsed.kind, "cosmos")
        self.assertEqual(parsed.value, VALID_SEI)

    def test_single_character_typo_is_caught(self) -> None:
        charset = address_mod.BECH32_CHARSET
        swapped = charset[(charset.index(VALID_SEI[-1]) + 1) % len(charset)]
        with self.assertRaises(PaymentError) as caught:
            address_mod.parse(VALID_SEI[:-1] + swapped)
        self.assertIn("checksum", str(caught.exception))

    def test_rejects_other_chain_prefix(self) -> None:
        with self.assertRaises(PaymentError):
            address_mod.parse(bech32_encode("cosmos", bytes(range(20))))

    def test_rejects_mixed_case(self) -> None:
        mixed = VALID_SEI[:6].upper() + VALID_SEI[6:]
        with self.assertRaises(PaymentError):
            address_mod.parse(mixed)

    def test_rejects_garbage(self) -> None:
        with self.assertRaises(PaymentError):
            address_mod.parse("definitely-not-an-address")


class TestMoneyArithmetic(unittest.TestCase):
    def test_format_round_trips(self) -> None:
        for usei in (0, 1, 999_999, USEI_PER_SEI, 204_300, 123_456_789):
            self.assertEqual(parse_sei(format_sei(usei)), usei)

    def test_format_pads_to_six_places(self) -> None:
        self.assertEqual(format_sei(1), "0.000001")
        self.assertEqual(format_sei(USEI_PER_SEI), "1.000000")

    def test_rejects_sub_usei_precision(self) -> None:
        with self.assertRaises(PaymentError) as caught:
            parse_sei("1.0000001")
        self.assertIn("6 decimal", str(caught.exception))

    def test_rejects_negative(self) -> None:
        with self.assertRaises(PaymentError):
            parse_sei("-1.0")

    def test_no_float_anywhere_in_a_quote(self) -> None:
        """Every numeric field in a quote document must be an int."""
        quote = price_build(
            node_kinds=["endpoint", "store"], output_bytes=5000, rigor="extreme"
        )

        def walk(value: object, path: str = "$") -> None:
            if isinstance(value, float):
                self.fail(f"float found at {path}")
            if isinstance(value, dict):
                for key, sub in value.items():
                    walk(sub, f"{path}.{key}")
            elif isinstance(value, list):
                for index, sub in enumerate(value):
                    walk(sub, f"{path}[{index}]")

        walk(quote.document())

    def test_rigor_multiplier_rounds_up(self) -> None:
        """Ceiling division: the operator is never shortchanged by truncation."""
        quote = price_build(node_kinds=["store"], output_bytes=1, rigor="strict")
        expected = -(-quote.subtotal_usei * RIGOR_BASIS_POINTS["strict"] // 10_000)
        self.assertEqual(quote.total_usei, expected)

    def test_output_bytes_round_up_to_kib(self) -> None:
        one_byte = price_build(node_kinds=["store"], output_bytes=1, rigor="standard")
        exact_kib = price_build(node_kinds=["store"], output_bytes=1024, rigor="standard")
        self.assertEqual(one_byte.total_usei, exact_kib.total_usei)

    def test_extreme_costs_more_than_lax(self) -> None:
        kinds = ["endpoint", "service"]
        lax = price_build(node_kinds=kinds, output_bytes=2048, rigor="lax")
        extreme = price_build(node_kinds=kinds, output_bytes=2048, rigor="extreme")
        self.assertGreater(extreme.total_usei, lax.total_usei)

    def test_unknown_node_kind_rejected(self) -> None:
        with self.assertRaises(PaymentError):
            price_build(node_kinds=["quantum"], output_bytes=0, rigor="standard")

    def test_catalog_is_publishable_without_credentials(self) -> None:
        published = published_catalog()
        self.assertEqual(published["denom"], "usei")
        self.assertTrue(published["items"])
        self.assertIn("non-custodial", published["note"])


class TestGateway(unittest.TestCase):
    def config(self, **kwargs) -> Config:
        from forge.config import NETWORKS

        defaults = dict(rigor=Rigor.STANDARD, network=NETWORKS["atlantic-2"], payee=VALID_SEI)
        defaults.update(kwargs)
        return Config(**defaults)

    def test_reference_binds_to_the_build(self) -> None:
        config = self.config()
        first = build_request(
            config, merkle_root="aa" * 32, node_kinds=["store"], output_bytes=100
        )
        second = build_request(
            config, merkle_root="bb" * 32, node_kinds=["store"], output_bytes=100
        )
        self.assertNotEqual(
            first.reference, second.reference,
            "a payment for one build must not satisfy another",
        )

    def test_reference_binds_to_the_amount(self) -> None:
        from forge.payments.catalog import price_build as pb

        cheap = pb(node_kinds=["store"], output_bytes=0, rigor="lax")
        dear = pb(node_kinds=["store"], output_bytes=0, rigor="extreme")
        self.assertNotEqual(
            derive_reference("aa" * 32, cheap, VALID_SEI),
            derive_reference("aa" * 32, dear, VALID_SEI),
        )

    def test_reference_binds_to_the_payee(self) -> None:
        from forge.payments.catalog import price_build as pb

        quote = pb(node_kinds=["store"], output_bytes=0, rigor="standard")
        other = bech32_encode("sei", bytes(range(1, 21)))
        self.assertNotEqual(
            derive_reference("aa" * 32, quote, VALID_SEI),
            derive_reference("aa" * 32, quote, other),
        )

    def test_request_is_deterministic(self) -> None:
        config = self.config()
        args = dict(merkle_root="cc" * 32, node_kinds=["endpoint"], output_bytes=4096)
        self.assertEqual(
            build_request(config, **args).document(),
            build_request(config, **args).document(),
        )

    def test_request_round_trips_through_json(self) -> None:
        config = self.config()
        original = build_request(
            config, merkle_root="dd" * 32, node_kinds=["model"], output_bytes=2048
        )
        restored = request_from_document(original.document())
        self.assertEqual(restored.reference, original.reference)
        self.assertEqual(restored.amount_usei, original.amount_usei)
        self.assertEqual(restored.payee, original.payee)

    def test_missing_payee_is_a_clear_error(self) -> None:
        config = self.config(payee=None)
        with self.assertRaises(PaymentError) as caught:
            build_request(config, merkle_root="ee" * 32, node_kinds=["store"], output_bytes=0)
        self.assertIn("FORGE_SEI_PAYEE", str(caught.exception))

    def test_invalid_payee_rejected_before_any_network_call(self) -> None:
        config = self.config(payee="sei1nonsense")
        with self.assertRaises(PaymentError):
            build_request(config, merkle_root="ff" * 32, node_kinds=["store"], output_bytes=0)

    def test_request_document_carries_no_secret(self) -> None:
        config = self.config()
        document = build_request(
            config, merkle_root="ab" * 32, node_kinds=["store"], output_bytes=0
        ).document()
        serialised = repr(document).lower()
        for forbidden in ("privkey", "private_key", "mnemonic", "seed phrase", "secret"):
            self.assertNotIn(forbidden, serialised)
        self.assertIn("never holds a private key", document["custody"])


class TestMainnetGuardrail(unittest.TestCase):
    def mainnet_config(self, allow: bool) -> Config:
        from forge.config import NETWORKS

        return Config(network=NETWORKS["pacific-1"], allow_mainnet=allow, payee=VALID_SEI)

    def test_mainnet_refused_without_opt_in(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            self.mainnet_config(False).require_mainnet_opt_in()
        self.assertIn("FORGE_ALLOW_MAINNET", str(caught.exception))

    def test_mainnet_allowed_with_opt_in(self) -> None:
        self.mainnet_config(True).require_mainnet_opt_in()  # must not raise

    def test_testnet_needs_no_opt_in(self) -> None:
        from forge.config import NETWORKS

        Config(network=NETWORKS["atlantic-2"]).require_mainnet_opt_in()

    def test_build_request_refuses_mainnet_without_opt_in(self) -> None:
        with self.assertRaises(ConfigError):
            build_request(
                self.mainnet_config(False),
                merkle_root="aa" * 32,
                node_kinds=["store"],
                output_bytes=0,
            )

    def test_default_network_is_not_mainnet(self) -> None:
        from forge.config import DEFAULT_NETWORK, NETWORKS

        self.assertFalse(NETWORKS[DEFAULT_NETWORK].is_mainnet)


class TestNoCustody(unittest.TestCase):
    """Structural proof that no signing or key handling exists in payments."""

    @staticmethod
    def code_only(module) -> str:
        """Module source with comments and string literals stripped.

        Scanning raw source would match prose -- the sei client's own docstring
        says "no broadcast path". Only executable tokens are evidence.
        """
        import inspect
        import io
        import tokenize

        source = inspect.getsource(module)
        kept: list[str] = []
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type in (tokenize.COMMENT, tokenize.STRING):
                continue
            kept.append(token.string)
        return " ".join(kept).lower()

    def test_no_signing_capability_in_payment_modules(self) -> None:
        from forge.payments import gateway, sei

        banned = (
            "private_key", "privkey", "mnemonic", "sign_tx", "signtx",
            "broadcast", "send_transaction", "eth_sendrawtransaction",
            "eth_sendtransaction", "secp256k1", "keyring", "wallet",
        )
        for module in (gateway, sei):
            code = self.code_only(module)
            for token in banned:
                self.assertNotIn(
                    token, code,
                    f"{module.__name__} must contain no key handling; found {token!r}",
                )

    def test_no_outbound_write_rpc_methods(self) -> None:
        """Every JSON-RPC method named in the client must be a read."""
        import inspect
        import re

        from forge.payments import sei

        methods = set(re.findall(r'"(eth_[a-zA-Z]+)"', inspect.getsource(sei)))
        writes = {m for m in methods if "send" in m.lower() or "sign" in m.lower()}
        self.assertEqual(writes, set(), f"write-capable RPC methods present: {writes}")

    def test_sei_client_exposes_no_write_methods(self) -> None:
        from forge.payments.sei import SeiClient

        public = [name for name in dir(SeiClient) if not name.startswith("_")]
        self.assertEqual(sorted(public), ["find_transfer", "latest_height"])


if __name__ == "__main__":
    unittest.main()
