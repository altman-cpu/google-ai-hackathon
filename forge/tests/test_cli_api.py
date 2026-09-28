"""CLI behaviour, manifest signing, and the HTTP surface."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from forge.canonical import loads
from forge.cli import main
from forge.errors import IntegrityError, PaymentError
from forge.signing import manifest as manifest_mod
from forge.signing import pgp
from forge.transform import Artifact

INTENT = {
    "schema": "forge.intent/v1",
    "name": "cli_demo",
    "objective": "Exercise the CLI end to end.",
    "network": {
        "nodes": [
            {"id": "intake", "kind": "endpoint", "description": "Front door."},
            {"id": "ledger", "kind": "store", "description": "Storage."},
        ],
        "edges": [
            {"from": "intake", "to": "ledger", "carries": "Record",
             "constraints": {"auth": "required", "idempotent": True}}
        ],
    },
}


class CliTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.intent_path = self.root / "intent.json"
        self.intent_path.write_text(json.dumps(INTENT), encoding="utf-8")
        self.workdir = self.root / "state"

    def run_cli(self, *args: str) -> tuple[int, str]:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main(["--workdir", str(self.workdir), *args])
        return code, buffer.getvalue()

    def run_json(self, *args: str) -> tuple[int, dict]:
        code, output = self.run_cli(*args, "--json")
        return code, loads(output)


class TestCliCommands(CliTestCase):
    def test_catalog_needs_no_credentials_or_network(self) -> None:
        code, payload = self.run_json("catalog")
        self.assertEqual(code, 0)
        self.assertEqual(payload["denom"], "usei")
        self.assertTrue(payload["items"])

    def test_validate(self) -> None:
        code, payload = self.run_json("validate", str(self.intent_path))
        self.assertEqual(code, 0)
        self.assertTrue(payload["valid"])
        self.assertEqual(payload["nodes"], 2)

    def test_design_orders_producers_first(self) -> None:
        code, payload = self.run_json("design", str(self.intent_path))
        self.assertEqual(code, 0)
        self.assertEqual(payload["order"], ["intake", "ledger"])

    def test_build_writes_a_tree(self) -> None:
        out = self.root / "out"
        code, payload = self.run_json("build", str(self.intent_path), "--out", str(out))
        self.assertEqual(code, 0)
        self.assertGreater(payload["artifact_count"], 0)
        self.assertTrue((out / "forge-manifest.json").exists())

    def test_dry_run_writes_nothing(self) -> None:
        out = self.root / "dry"
        code, _ = self.run_json("build", str(self.intent_path), "--out", str(out), "--dry-run")
        self.assertEqual(code, 0)
        self.assertFalse(out.exists())

    def test_quote_without_payee_issues_no_request(self) -> None:
        code, payload = self.run_json("quote", str(self.intent_path))
        self.assertEqual(code, 0)
        self.assertIsNone(payload.get("payment_request"))
        self.assertGreater(payload["quote"]["total_usei"], 0)

    def test_quote_with_payee_issues_a_request(self) -> None:
        from tests.test_payments import VALID_SEI

        code, payload = self.run_json("quote", str(self.intent_path), "--payee", VALID_SEI)
        self.assertEqual(code, 0)
        request = payload["payment_request"]
        self.assertEqual(request["payee"], VALID_SEI)
        self.assertTrue(request["reference"].startswith("forge:"))

    def test_generators_are_listed(self) -> None:
        code, payload = self.run_json("generators")
        self.assertEqual(code, 0)
        self.assertIn("drf_endpoint", payload["generators"])

    def test_doctor_reports_environment(self) -> None:
        code, payload = self.run_json("doctor")
        self.assertEqual(code, 0)
        self.assertIn("gpg", payload)
        self.assertFalse(payload["network"]["is_mainnet"], "default must be testnet")

    def test_iceberg_surface_after_a_build(self) -> None:
        self.run_cli("build", str(self.intent_path), "--out", str(self.root / "o"))
        code, payload = self.run_json("iceberg")
        self.assertEqual(code, 0)
        self.assertGreater(payload["object_count"], 0)

    def test_iceberg_fsck_is_clean(self) -> None:
        self.run_cli("build", str(self.intent_path), "--out", str(self.root / "o"))
        code, payload = self.run_json("iceberg", "--fsck")
        self.assertEqual(code, 0)
        self.assertTrue(payload["ok"])


class TestCliExitCodes(CliTestCase):
    def test_malformed_intent_exits_nonzero(self) -> None:
        bad = self.root / "bad.json"
        bad.write_text('{"schema": "wrong/v1"}', encoding="utf-8")
        code, _ = self.run_cli("validate", str(bad))
        self.assertNotEqual(code, 0)

    def test_missing_file_exits_nonzero(self) -> None:
        code, _ = self.run_cli("validate", str(self.root / "nope.json"))
        self.assertNotEqual(code, 0)

    def test_mainnet_without_opt_in_is_refused(self) -> None:
        from tests.test_payments import VALID_SEI

        code, _ = self.run_cli(
            "quote", str(self.intent_path), "--network", "pacific-1", "--payee", VALID_SEI
        )
        self.assertNotEqual(code, 0, "mainnet must refuse without an explicit opt-in")

    def test_verify_on_unsigned_tree_reports_unverified(self) -> None:
        out = self.root / "out"
        self.run_cli("build", str(self.intent_path), "--out", str(out), "--no-sign")
        code, payload = self.run_json("verify", str(out))
        self.assertEqual(code, IntegrityError.exit_code)
        self.assertTrue(payload["integrity"]["ok"], "contents should still match")
        self.assertFalse(payload["verified"], "unsigned output must not count as verified")

    def test_verify_detects_tampering_on_disk(self) -> None:
        out = self.root / "out"
        self.run_cli("build", str(self.intent_path), "--out", str(out), "--no-sign")
        target = next(out.rglob("*.py"))
        target.write_bytes(target.read_bytes() + b"\n# injected\n")
        code, payload = self.run_json("verify", str(out))
        self.assertNotEqual(code, 0)
        self.assertFalse(payload["integrity"]["ok"])


class TestManifest(unittest.TestCase):
    def artifacts(self) -> list[Artifact]:
        return [
            Artifact(path="a.py", content=b"a = 1\n"),
            Artifact(path="b.py", content=b"b = 2\n"),
        ]

    def manifest(self):
        return manifest_mod.build(
            intent_name="demo",
            intent_digest="aa" * 32,
            plan_digest="bb" * 32,
            chain_root="cc" * 32,
            artifacts=self.artifacts(),
            rigor="strict",
        )

    def test_bytes_are_stable(self) -> None:
        self.assertEqual(self.manifest().bytes(), self.manifest().bytes())

    def test_bytes_end_with_a_newline(self) -> None:
        self.assertTrue(self.manifest().bytes().endswith(b"\n"))

    def test_carries_an_op_return_anchor(self) -> None:
        anchor = self.manifest().document()["anchor"]
        self.assertEqual(anchor["chain"], "bitcoin")
        self.assertLessEqual(len(bytes.fromhex(anchor["op_return_hex"])), 80)

    def test_integrity_passes_on_matching_artifacts(self) -> None:
        self.assertEqual(
            manifest_mod.verify_integrity(self.manifest().document(), self.artifacts()), []
        )

    def test_integrity_catches_a_changed_byte(self) -> None:
        mutated = [Artifact(path="a.py", content=b"a = 2\n"), self.artifacts()[1]]
        problems = manifest_mod.verify_integrity(self.manifest().document(), mutated)
        self.assertTrue(any("digest mismatch" in p for p in problems))

    def test_integrity_catches_a_missing_file(self) -> None:
        problems = manifest_mod.verify_integrity(
            self.manifest().document(), self.artifacts()[:1]
        )
        self.assertTrue(any("missing on disk" in p for p in problems))

    def test_integrity_catches_an_extra_file(self) -> None:
        extra = self.artifacts() + [Artifact(path="c.py", content=b"c = 3\n")]
        problems = manifest_mod.verify_integrity(self.manifest().document(), extra)
        self.assertTrue(any("absent from the manifest" in p for p in problems))

    def test_manifest_lists_no_content(self) -> None:
        document = self.manifest().document()
        self.assertNotIn("a = 1", repr(document))


class TestPgpDegradation(unittest.TestCase):
    """Behaviour when gpg is absent must be honest, not silently unsigned."""

    def test_verify_without_gpg_reports_unavailable(self) -> None:
        result = pgp.verify_detached(b"data", "sig", binary="definitely-not-a-real-binary")
        self.assertFalse(result.valid)
        self.assertEqual(result.status, "UNAVAILABLE")

    def test_signing_without_gpg_raises_with_guidance(self) -> None:
        from forge.errors import SigningError

        with self.assertRaises(SigningError) as caught:
            pgp.sign_detached(b"data", None, binary="definitely-not-a-real-binary")
        self.assertIn("FORGE_GPG_KEY", str(caught.exception))

    @unittest.skipUnless(pgp.is_available(), "gpg not installed")
    def test_sign_and_verify_round_trip(self) -> None:
        signature = pgp.sign_detached(b"payload")
        self.assertTrue(pgp.verify_detached(b"payload", signature.armored).valid)
        self.assertFalse(pgp.verify_detached(b"tampered", signature.armored).valid)


class TestHttpApi(unittest.TestCase):
    """Drive the real server over a loopback socket."""

    @classmethod
    def setUpClass(cls) -> None:
        import threading
        from http.server import ThreadingHTTPServer

        from forge.api.server import ForgeHandler
        from forge.config import Config

        cls.tmp = tempfile.TemporaryDirectory()
        config = Config(workdir=Path(cls.tmp.name) / "state")
        handler = type("Bound", (ForgeHandler,), {"config": config, "log_message": lambda *a: None})
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def request(self, method: str, path: str, body: dict | None = None):
        import urllib.error
        import urllib.request

        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=data,
            headers={"Content-Type": "application/json"},
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_healthz(self) -> None:
        status, payload = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])

    def test_catalog(self) -> None:
        status, payload = self.request("GET", "/v1/catalog")
        self.assertEqual(status, 200)
        self.assertEqual(payload["denom"], "usei")

    def test_networks_marks_mainnet(self) -> None:
        status, payload = self.request("GET", "/v1/networks")
        self.assertEqual(status, 200)
        mainnets = [n["name"] for n in payload["networks"] if n["is_mainnet"]]
        self.assertEqual(mainnets, ["pacific-1"])

    def test_validate(self) -> None:
        status, payload = self.request("POST", "/v1/validate", {"intent": INTENT})
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])

    def test_design(self) -> None:
        status, payload = self.request("POST", "/v1/design", {"intent": INTENT})
        self.assertEqual(status, 200)
        self.assertEqual(payload["plan"]["order"], ["intake", "ledger"])

    def test_build_returns_tips_by_default(self) -> None:
        status, payload = self.request("POST", "/v1/build", {"intent": INTENT})
        self.assertEqual(status, 200)
        self.assertTrue(payload["artifacts"])
        self.assertNotIn("content_base64", payload["artifacts"][0])

    def test_build_returns_content_on_request(self) -> None:
        status, payload = self.request(
            "POST", "/v1/build", {"intent": INTENT, "include_content": True}
        )
        self.assertEqual(status, 200)
        self.assertIn("content_base64", payload["artifacts"][0])

    def test_object_body_requires_a_full_digest(self) -> None:
        status, payload = self.request("GET", "/v1/objects/abc123")
        self.assertEqual(status, 400)
        self.assertIn("truncated", payload["error"]["message"])

    def test_unknown_route_is_404(self) -> None:
        status, _ = self.request("GET", "/v1/nope")
        self.assertEqual(status, 404)

    def test_malformed_intent_is_400_not_500(self) -> None:
        status, payload = self.request("POST", "/v1/validate", {"intent": {"schema": "bad"}})
        self.assertEqual(status, 400)
        self.assertFalse(payload["ok"])


if __name__ == "__main__":
    unittest.main()
