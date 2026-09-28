"""The iceberg store's three invariants: tip above water, no blocks, no key cut."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from forge.errors import IntegrityError
from forge.hashing import hash256, hex_be
from forge.iceberg import Iceberg


class IcebergTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Iceberg(Path(self.tmp.name) / "iceberg")
        self.store.ensure()


class TestRoundTrip(IcebergTestCase):
    def test_put_then_get(self) -> None:
        tip = self.store.put(b"hello world", kind="blob", media_type="text/plain")
        self.assertEqual(self.store.body(tip.digest), b"hello world")

    def test_digest_is_content_addressed(self) -> None:
        tip = self.store.put(b"payload", kind="blob")
        self.assertEqual(tip.digest, hex_be(hash256(b"payload")))

    def test_identical_content_deduplicates(self) -> None:
        first = self.store.put(b"same", kind="blob")
        second = self.store.put(b"same", kind="blob")
        self.assertEqual(first.digest, second.digest)
        self.assertEqual(len(list(self.store.tips())), 1)

    def test_documents_round_trip(self) -> None:
        tip = self.store.put_document({"b": 2, "a": 1}, kind="document")
        self.assertEqual(self.store.document(tip.digest), {"a": 1, "b": 2})

    def test_key_order_does_not_change_the_digest(self) -> None:
        first = self.store.put_document({"a": 1, "b": 2}, kind="document")
        second = self.store.put_document({"b": 2, "a": 1}, kind="document")
        self.assertEqual(first.digest, second.digest)


class TestTipAboveWater(IcebergTestCase):
    def test_tip_reveals_shape_but_not_content(self) -> None:
        tip = self.store.put(b"CLASSIFIED PAYLOAD", kind="blob", path="secret.bin")
        document = tip.document()
        self.assertEqual(document["size"], 18)
        self.assertEqual(document["path"], "secret.bin")
        self.assertNotIn("CLASSIFIED", repr(document))
        self.assertNotIn("content", document)

    def test_surface_is_publishable(self) -> None:
        self.store.put(b"one secret", kind="blob", path="a")
        self.store.put(b"another secret", kind="blob", path="b")
        surface = self.store.surface()
        self.assertEqual(surface["object_count"], 2)
        self.assertEqual(surface["submerged_bytes"], len(b"one secret") + len(b"another secret"))
        self.assertNotIn("secret", repr(surface))

    def test_reading_a_tip_does_not_require_the_body(self) -> None:
        tip = self.store.put(b"body bytes", kind="blob")
        (self.store.body_dir / tip.digest).unlink()
        self.assertEqual(self.store.tip(tip.digest).size, 10)


class TestNoBlocks(IcebergTestCase):
    def test_body_is_one_whole_file(self) -> None:
        payload = b"z" * 500_000
        tip = self.store.put(payload, kind="blob")
        files = list(self.store.body_dir.iterdir())
        self.assertEqual(len(files), 1, "a body must never be split across files")
        self.assertEqual(files[0].stat().st_size, len(payload))
        self.assertEqual(self.store.body(tip.digest), payload)

    def test_no_chunk_or_part_files_are_left_behind(self) -> None:
        self.store.put(b"y" * 300_000, kind="blob")
        names = [path.name for path in self.store.body_dir.iterdir()]
        for name in names:
            self.assertNotIn(".part", name)
            self.assertNotIn(".chunk", name)
            self.assertFalse(name.startswith(".tmp-"), "temp file survived an atomic write")

    def test_empty_body_is_allowed(self) -> None:
        tip = self.store.put(b"", kind="blob")
        self.assertEqual(self.store.body(tip.digest), b"")


class TestNoKeyCut(IcebergTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.tip = self.store.put(b"addressed by its whole digest", kind="blob")

    def test_full_key_resolves(self) -> None:
        self.assertTrue(self.store.has(self.tip.digest))

    def test_truncated_key_refused(self) -> None:
        with self.assertRaises(IntegrityError) as caught:
            self.store.body(self.tip.digest[:16])
        self.assertIn("truncated or prefix", str(caught.exception))

    def test_prefix_lookup_refused(self) -> None:
        with self.assertRaises(IntegrityError):
            self.store.has(self.tip.digest[:8])

    def test_uppercase_key_refused(self) -> None:
        """One canonical spelling per key; case variants are not aliases."""
        with self.assertRaises(IntegrityError):
            self.store.body(self.tip.digest.upper())

    def test_keys_are_not_fanned_into_subdirectories(self) -> None:
        for entry in self.store.body_dir.iterdir():
            self.assertTrue(entry.is_file(), "digests must not be split into shard directories")
            self.assertEqual(len(entry.name), 64)


class TestIntegrity(IcebergTestCase):
    def test_corrupted_body_is_detected_on_read(self) -> None:
        tip = self.store.put(b"original content", kind="blob")
        (self.store.body_dir / tip.digest).write_bytes(b"tampered content")
        with self.assertRaises(IntegrityError):
            self.store.body(tip.digest)

    def test_fsck_finds_corruption(self) -> None:
        tip = self.store.put(b"original content", kind="blob")
        (self.store.body_dir / tip.digest).write_bytes(b"tampered content")
        self.assertTrue(self.store.fsck())

    def test_fsck_finds_orphaned_bodies(self) -> None:
        tip = self.store.put(b"soon to be orphaned", kind="blob")
        (self.store.tip_dir / f"{tip.digest}.json").unlink()
        problems = self.store.fsck()
        self.assertTrue(any("orphan" in problem for problem in problems))

    def test_healthy_store_reports_nothing(self) -> None:
        self.store.put(b"a", kind="blob")
        self.store.put_document({"k": "v"}, kind="document")
        self.assertEqual(self.store.fsck(), [])

    def test_missing_object_is_a_clear_error(self) -> None:
        with self.assertRaises(IntegrityError):
            self.store.body("00" * 32)


if __name__ == "__main__":
    unittest.main()
