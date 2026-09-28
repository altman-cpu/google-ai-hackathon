"""Hashing, merkle trees, and canonical serialisation."""

from __future__ import annotations

import unittest

from forge.canonical import canonical_bytes, canonical_json, loads
from forge.errors import IntegrityError
from forge.hashing import (
    ZERO_DIGEST,
    from_hex_be,
    hash256,
    hex_be,
    merkle_path,
    merkle_root,
    merkle_verify,
    op_return_payload,
    sha256,
)


class TestHash256(unittest.TestCase):
    def test_is_double_sha256(self) -> None:
        data = b"canceralyze"
        self.assertEqual(hash256(data), sha256(sha256(data)))

    def test_differs_from_single_sha256(self) -> None:
        self.assertNotEqual(hash256(b"x"), sha256(b"x"))

    def test_known_vector(self) -> None:
        # hash256("hello") is a widely published Bitcoin test value.
        self.assertEqual(
            hash256(b"hello").hex(),
            "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50",
        )

    def test_display_order_is_reversed(self) -> None:
        digest = hash256(b"hello")
        self.assertEqual(hex_be(digest), digest[::-1].hex())
        self.assertEqual(from_hex_be(hex_be(digest)), digest)

    def test_rejects_wrong_length(self) -> None:
        with self.assertRaises(IntegrityError):
            hex_be(b"\x00" * 31)


class TestMerkle(unittest.TestCase):
    def leaves(self, count: int) -> list[bytes]:
        return [hash256(f"leaf-{i}".encode()) for i in range(count)]

    def test_empty_tree_is_zero(self) -> None:
        self.assertEqual(merkle_root([]), ZERO_DIGEST)

    def test_single_leaf_is_itself(self) -> None:
        leaf = hash256(b"only")
        self.assertEqual(merkle_root([leaf]), leaf)

    def test_two_leaves(self) -> None:
        a, b = self.leaves(2)
        self.assertEqual(merkle_root([a, b]), hash256(a + b))

    def test_odd_level_duplicates_last_node(self) -> None:
        """Bitcoin's rule: an odd level promotes a copy of its final node."""
        a, b, c = self.leaves(3)
        expected = hash256(hash256(a + b) + hash256(c + c))
        self.assertEqual(merkle_root([a, b, c]), expected)

    def test_order_matters(self) -> None:
        a, b = self.leaves(2)
        self.assertNotEqual(merkle_root([a, b]), merkle_root([b, a]))

    def test_strict_mode_rejects_duplicate_leaves(self) -> None:
        """CVE-2012-2459: duplicate leaves make the root ambiguous."""
        leaf = hash256(b"dup")
        with self.assertRaises(IntegrityError) as caught:
            merkle_root([leaf, leaf])
        self.assertIn("CVE-2012-2459", str(caught.exception))

    def test_cve_2012_2459_collision_is_blocked(self) -> None:
        """[a,b,c] and [a,b,c,c] collide under Bitcoin's rule; strict blocks it."""
        a, b, c = self.leaves(3)
        self.assertEqual(
            merkle_root([a, b, c], strict=False),
            merkle_root([a, b, c, c], strict=False),
        )
        with self.assertRaises(IntegrityError):
            merkle_root([a, b, c, c], strict=True)

    def test_inclusion_proofs_verify(self) -> None:
        for count in (1, 2, 3, 5, 8, 13):
            leaves = self.leaves(count)
            root = merkle_root(leaves)
            for index, leaf in enumerate(leaves):
                path = merkle_path(leaves, index)
                self.assertTrue(
                    merkle_verify(leaf, index, path, root),
                    f"proof failed for leaf {index} of {count}",
                )

    def test_forged_proof_fails(self) -> None:
        leaves = self.leaves(5)
        root = merkle_root(leaves)
        path = merkle_path(leaves, 2)
        self.assertFalse(merkle_verify(hash256(b"not-in-tree"), 2, path, root))


class TestOpReturn(unittest.TestCase):
    def test_payload_fits_bitcoin_limit(self) -> None:
        payload = op_return_payload(hash256(b"root"))
        self.assertEqual(len(payload), 38)
        self.assertLessEqual(len(payload), 80)
        self.assertTrue(payload.startswith(b"FORGE1"))

    def test_oversized_magic_rejected(self) -> None:
        with self.assertRaises(IntegrityError):
            op_return_payload(hash256(b"root"), b"M" * 60)


class TestCanonical(unittest.TestCase):
    def test_key_order_is_irrelevant(self) -> None:
        self.assertEqual(
            canonical_bytes({"b": 1, "a": 2}),
            canonical_bytes({"a": 2, "b": 1}),
        )

    def test_no_insignificant_whitespace(self) -> None:
        self.assertEqual(canonical_json({"a": [1, 2]}), '{"a":[1,2]}')

    def test_floats_are_rejected(self) -> None:
        with self.assertRaises(IntegrityError) as caught:
            canonical_bytes({"amount": 1.5})
        self.assertIn("float", str(caught.exception))

    def test_float_literals_rejected_on_parse(self) -> None:
        with self.assertRaises(IntegrityError):
            loads('{"amount": 1.5}')

    def test_nested_float_is_caught(self) -> None:
        with self.assertRaises(IntegrityError):
            canonical_bytes({"a": {"b": [1, 2.0]}})

    def test_tuples_and_lists_agree(self) -> None:
        self.assertEqual(canonical_bytes({"a": (1, 2)}), canonical_bytes({"a": [1, 2]}))

    def test_unicode_survives(self) -> None:
        self.assertEqual(loads(canonical_json({"k": "café"}))["k"], "café")

    def test_rejects_non_string_keys(self) -> None:
        with self.assertRaises(IntegrityError):
            canonical_bytes({1: "a"})

    def test_rejects_unknown_types(self) -> None:
        with self.assertRaises(IntegrityError):
            canonical_bytes({"a": {1, 2}})


if __name__ == "__main__":
    unittest.main()
