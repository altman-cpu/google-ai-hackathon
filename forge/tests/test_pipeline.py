"""Intent validation, design resolution, transforms, and the full pipeline."""

from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from forge import design as design_mod
from forge import intent as intent_mod
from forge import pipeline
from forge.config import Config, Rigor
from forge.errors import DesignError, GeneratorError, IntegrityError, IntentError, PolicyError
from forge.transform import Artifact, TransformChain, TransformObject

BASE_INTENT = {
    "schema": "forge.intent/v1",
    "name": "demo",
    "objective": "A minimal two-node network for tests.",
    "network": {
        "nodes": [
            {"id": "intake", "kind": "endpoint", "description": "Front door."},
            {"id": "ledger", "kind": "store", "description": "Where it lands."},
        ],
        "edges": [
            {
                "from": "intake",
                "to": "ledger",
                "carries": "Record",
                "constraints": {"auth": "required", "idempotent": True, "max_bytes": 4096},
            }
        ],
    },
}


def make_intent(**mutations) -> dict:
    document = copy.deepcopy(BASE_INTENT)
    document.update(mutations)
    return document


class TestIntentValidation(unittest.TestCase):
    def test_valid_intent_parses(self) -> None:
        intent, warnings = intent_mod.parse(make_intent())
        self.assertEqual(intent.name, "demo")
        self.assertEqual(len(intent.nodes), 2)
        self.assertEqual(warnings, [])

    def test_digest_is_authoring_order_independent(self) -> None:
        first, _ = intent_mod.parse(make_intent())
        shuffled = copy.deepcopy(BASE_INTENT)
        shuffled["network"]["nodes"].reverse()
        second, _ = intent_mod.parse(shuffled)
        self.assertEqual(first.digest_hex, second.digest_hex)

    def test_digest_changes_with_content(self) -> None:
        first, _ = intent_mod.parse(make_intent())
        second, _ = intent_mod.parse(make_intent(objective="Something else entirely."))
        self.assertNotEqual(first.digest_hex, second.digest_hex)

    def test_wrong_schema_rejected(self) -> None:
        with self.assertRaises(IntentError):
            intent_mod.parse(make_intent(schema="something/v9"))

    def test_edge_to_unknown_node_rejected(self) -> None:
        document = make_intent()
        document["network"]["edges"][0]["to"] = "nowhere"
        with self.assertRaises(IntentError) as caught:
            intent_mod.parse(document)
        self.assertIn("unknown node", str(caught.exception))

    def test_cycle_rejected_with_the_path(self) -> None:
        document = make_intent()
        document["network"]["edges"].append(
            {"from": "ledger", "to": "intake", "carries": "Ack"}
        )
        with self.assertRaises(IntentError) as caught:
            intent_mod.parse(document)
        self.assertIn("cycle", str(caught.exception))

    def test_self_loop_rejected(self) -> None:
        document = make_intent()
        document["network"]["edges"][0]["to"] = "intake"
        with self.assertRaises(IntentError):
            intent_mod.parse(document)

    def test_duplicate_node_id_rejected(self) -> None:
        document = make_intent()
        document["network"]["nodes"].append(dict(document["network"]["nodes"][0]))
        with self.assertRaises(IntentError):
            intent_mod.parse(document)

    def test_unknown_constraint_rejected_not_ignored(self) -> None:
        """A typo'd constraint that silently does nothing is worse than an error."""
        document = make_intent()
        document["network"]["edges"][0]["constraints"]["authh"] = "required"
        with self.assertRaises(IntentError) as caught:
            intent_mod.parse(document)
        self.assertIn("unknown key", str(caught.exception))

    def test_boolean_is_not_accepted_as_integer(self) -> None:
        document = make_intent()
        document["network"]["edges"][0]["constraints"]["max_bytes"] = True
        with self.assertRaises(IntentError):
            intent_mod.parse(document)

    def test_bad_node_kind_lists_the_valid_ones(self) -> None:
        document = make_intent()
        document["network"]["nodes"][0]["kind"] = "microservice"
        with self.assertRaises(IntentError) as caught:
            intent_mod.parse(document)
        self.assertIn("endpoint", str(caught.exception))


class TestWarnings(unittest.TestCase):
    def test_pii_without_auth_warns(self) -> None:
        document = make_intent()
        document["network"]["edges"][0]["constraints"] = {"auth": "none", "pii": True}
        _, warnings = intent_mod.parse(document)
        self.assertTrue(any("PII" in w for w in warnings))

    def test_retries_without_idempotency_warns(self) -> None:
        document = make_intent()
        document["network"]["edges"][0]["constraints"] = {"retries": 3, "idempotent": False}
        _, warnings = intent_mod.parse(document)
        self.assertTrue(any("idempotent" in w for w in warnings))

    def test_unauthenticated_front_door_warns(self) -> None:
        document = make_intent()
        document["network"]["edges"][0]["constraints"] = {}
        _, warnings = intent_mod.parse(document)
        self.assertTrue(any("entered from outside" in w for w in warnings))

    def test_strict_rigor_promotes_warnings_to_errors(self) -> None:
        with self.assertRaises(PolicyError):
            pipeline.apply_warning_policy(["something suspicious"], Rigor.STRICT)

    def test_standard_rigor_tolerates_warnings(self) -> None:
        pipeline.apply_warning_policy(["something suspicious"], Rigor.STANDARD)


class TestRigorFloor(unittest.TestCase):
    def test_intent_rigor_raises_but_never_lowers(self) -> None:
        intent, _ = intent_mod.parse(make_intent(rigor="extreme"))
        resolved = pipeline.effective_rigor(intent, Config(rigor=Rigor.LAX))
        self.assertEqual(resolved, Rigor.EXTREME)

    def test_config_can_raise_above_the_intent(self) -> None:
        intent, _ = intent_mod.parse(make_intent(rigor="lax"))
        resolved = pipeline.effective_rigor(intent, Config(rigor=Rigor.STRICT))
        self.assertEqual(resolved, Rigor.STRICT)

    def test_unknown_rigor_in_intent_is_an_error(self) -> None:
        intent, _ = intent_mod.parse(make_intent(rigor="paranoid"))
        with self.assertRaises(PolicyError):
            pipeline.effective_rigor(intent, Config())


class TestDesign(unittest.TestCase):
    def plan(self, document: dict | None = None) -> design_mod.Plan:
        intent, _ = intent_mod.parse(document or make_intent())
        return pipeline.design(intent, Config(), designer="deterministic")

    def test_producers_precede_consumers(self) -> None:
        order = [step.id for step in self.plan().steps]
        self.assertLess(order.index("intake"), order.index("ledger"))

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(self.plan().digest_hex, self.plan().digest_hex)

    def test_origin_inherits_auth_from_outbound(self) -> None:
        """The front door must not silently resolve to unauthenticated."""
        step = self.plan().step("intake")
        self.assertTrue(step.is_origin)
        self.assertEqual(step.effective_auth, "required")

    def test_origin_inherits_size_cap(self) -> None:
        self.assertEqual(self.plan().step("intake").max_bytes, 4096)

    def test_explicit_node_auth_overrides_derivation(self) -> None:
        document = make_intent()
        document["network"]["nodes"][0]["params"] = {"auth": "none"}
        self.assertEqual(self.plan(document).step("intake").effective_auth, "none")

    def test_idempotency_requires_unanimity(self) -> None:
        document = make_intent()
        document["network"]["nodes"].append(
            {"id": "other", "kind": "service", "description": "Second caller."}
        )
        document["network"]["edges"].append(
            {"from": "other", "to": "ledger", "carries": "Record",
             "constraints": {"idempotent": False}}
        )
        self.assertFalse(self.plan(document).step("ledger").is_idempotent)

    def test_tightest_constraint_wins(self) -> None:
        document = make_intent()
        document["network"]["nodes"].append(
            {"id": "other", "kind": "service", "description": "Second caller."}
        )
        document["network"]["edges"].append(
            {"from": "other", "to": "ledger", "carries": "Small",
             "constraints": {"max_bytes": 512}}
        )
        self.assertEqual(self.plan(document).step("ledger").max_bytes, 512)

    def test_designer_cannot_introduce_a_node(self) -> None:
        intent, _ = intent_mod.parse(make_intent())
        with self.assertRaises(DesignError) as caught:
            design_mod.resolve(intent, overrides={"ghost": {"route": "ghost"}})
        self.assertIn("never declared", str(caught.exception))

    def test_author_params_beat_designer_suggestions(self) -> None:
        document = make_intent()
        document["network"]["nodes"][0]["params"] = {"route": "author-chose-this"}
        intent, _ = intent_mod.parse(document)
        plan = design_mod.resolve(intent, overrides={"intake": {"route": "model-chose-this"}})
        self.assertEqual(plan.step("intake").params["route"], "author-chose-this")


class TestGeminiSanitiser(unittest.TestCase):
    def setUp(self) -> None:
        self.intent, _ = intent_mod.parse(make_intent())

    def sanitise(self, raw):
        from forge.llm.gemini import sanitise

        return sanitise(raw, self.intent)

    def test_hallucinated_node_dropped(self) -> None:
        self.assertEqual(self.sanitise({"imaginary": {"route": "x"}}), {})

    def test_unknown_parameter_dropped(self) -> None:
        result = self.sanitise({"intake": {"route": "ok", "backdoor": True}})
        self.assertEqual(result, {"intake": {"route": "ok"}})

    def test_invalid_http_method_dropped(self) -> None:
        result = self.sanitise({"intake": {"methods": ["post", "TRACE", "connect"]}})
        self.assertEqual(result, {"intake": {"methods": ["post"]}})

    def test_prose_response_yields_nothing(self) -> None:
        self.assertEqual(self.sanitise("Certainly! Here is your configuration:"), {})

    def test_bad_field_type_dropped(self) -> None:
        result = self.sanitise({"intake": {"fields": {"a": "str", "b": "wormhole"}}})
        self.assertEqual(result, {"intake": {"fields": {"a": "str"}}})

    def test_non_identifier_field_name_dropped(self) -> None:
        result = self.sanitise({"intake": {"fields": {"drop table users": "str"}}})
        self.assertEqual(result, {})


class TestTransforms(unittest.TestCase):
    def artifact(self, path: str = "a.py", content: bytes = b"x = 1\n") -> Artifact:
        return Artifact(path=path, content=content)

    def test_digest_covers_path(self) -> None:
        self.assertNotEqual(
            self.artifact("a.py").digest, self.artifact("b.py").digest
        )

    def test_digest_covers_mode(self) -> None:
        a = Artifact(path="s.sh", content=b"#!/bin/sh\n", mode=0o644)
        b = Artifact(path="s.sh", content=b"#!/bin/sh\n", mode=0o755)
        self.assertNotEqual(a.digest, b.digest)

    def test_absolute_path_rejected(self) -> None:
        with self.assertRaises(IntegrityError):
            Artifact(path="/etc/passwd", content=b"")

    def test_traversal_rejected(self) -> None:
        with self.assertRaises(IntegrityError):
            Artifact(path="../../etc/passwd", content=b"")

    def test_backslash_rejected(self) -> None:
        with self.assertRaises(IntegrityError):
            Artifact(path="a\\b.py", content=b"")

    def test_tip_never_contains_content(self) -> None:
        tip = self.artifact(content=b"SECRET VALUE").tip()
        self.assertNotIn("SECRET", repr(tip))
        self.assertNotIn("content", tip)

    def test_output_order_does_not_change_digest(self) -> None:
        one = self.artifact("one.py")
        two = self.artifact("two.py", b"y = 2\n")
        first = TransformObject(operation="t", outputs=(one, two))
        second = TransformObject(operation="t", outputs=(two, one))
        self.assertEqual(first.digest, second.digest)

    def test_duplicate_output_paths_rejected(self) -> None:
        with self.assertRaises(IntegrityError):
            TransformObject(
                operation="t", outputs=(self.artifact(), self.artifact(content=b"other"))
            )

    def test_chain_rejects_a_dangling_parent(self) -> None:
        chain = TransformChain(
            transforms=(TransformObject(operation="t", parents=("ab" * 32,)),)
        )
        with self.assertRaises(IntegrityError):
            chain.verify_links()

    def test_conflicting_content_across_transforms_rejected(self) -> None:
        from forge.transform import collect_artifacts

        a = TransformObject(operation="a", outputs=(self.artifact(content=b"one"),))
        b = TransformObject(operation="b", outputs=(self.artifact(content=b"two"),))
        with self.assertRaises(IntegrityError):
            collect_artifacts([a, b])


class TestBuild(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.workdir = Path(self.tmp.name) / "state"
        self.addCleanup(self.tmp.cleanup)

    def config(self, **kwargs) -> Config:
        defaults = dict(rigor=Rigor.STANDARD, workdir=self.workdir)
        defaults.update(kwargs)
        return Config(**defaults)

    def test_build_produces_artifacts_and_a_manifest(self) -> None:
        result = pipeline.build(make_intent(), self.config(), write=False, store=False)
        self.assertTrue(result.artifacts)
        self.assertEqual(len(result.manifest.merkle_root_hex), 64)
        self.assertEqual(result.manifest.intent_digest, result.intent.digest_hex)

    def test_build_is_byte_reproducible(self) -> None:
        config = self.config(rigor=Rigor.STRICT)
        first = pipeline.build(make_intent(), config, write=False, store=False)
        second = pipeline.build(make_intent(), config, write=False, store=False)
        self.assertEqual(first.chain.root_hex, second.chain.root_hex)
        self.assertEqual(first.manifest.merkle_root_hex, second.manifest.merkle_root_hex)
        for left, right in zip(first.artifacts, second.artifacts):
            self.assertEqual(left.content, right.content)

    def test_changing_intent_changes_every_downstream_digest(self) -> None:
        config = self.config()
        first = pipeline.build(make_intent(), config, write=False, store=False)
        mutated = make_intent()
        mutated["network"]["edges"][0]["constraints"]["max_bytes"] = 8192
        second = pipeline.build(mutated, config, write=False, store=False)
        self.assertNotEqual(first.intent.digest_hex, second.intent.digest_hex)
        self.assertNotEqual(first.plan.digest_hex, second.plan.digest_hex)
        self.assertNotEqual(first.chain.root_hex, second.chain.root_hex)
        self.assertNotEqual(first.manifest.merkle_root_hex, second.manifest.merkle_root_hex)

    def test_generated_python_actually_compiles(self) -> None:
        result = pipeline.build(make_intent(), self.config(), write=False, store=False)
        compiled = 0
        for artifact in result.artifacts:
            if artifact.path.endswith(".py"):
                compile(artifact.content.decode("utf-8"), artifact.path, "exec")
                compiled += 1
        self.assertGreater(compiled, 0)

    def test_intent_constraints_reach_the_generated_code(self) -> None:
        result = pipeline.build(make_intent(), self.config(), write=False, store=False)
        blob = b"\n".join(artifact.content for artifact in result.artifacts).decode()
        self.assertIn("IsAuthenticated", blob)      # auth: required
        self.assertIn("4096", blob)                  # max_bytes
        self.assertIn("Idempotency-Key", blob)       # idempotent: true

    def test_invoice_matches_the_quote_shown(self) -> None:
        """Regression: the invoice must never be priced below the quote.

        These are computed by separate code paths. The gateway once defaulted
        to config.rigor while the pipeline priced with the effective rigor, so
        an intent that raised the level via its own rigor floor produced an
        invoice a whole tier cheaper than the build it paid for.
        """
        from tests.test_payments import VALID_SEI

        # config says lax, the intent floor says strict: the two prices must
        # still agree, and both must reflect strict.
        result = pipeline.build(
            make_intent(rigor="strict"),
            self.config(rigor=Rigor.LAX, payee=VALID_SEI),
            write=False,
            store=False,
            sign=False,
        )
        self.assertIsNotNone(result.payment)
        self.assertEqual(result.rigor, Rigor.STRICT)
        self.assertEqual(result.quote.rigor, "strict")
        self.assertEqual(result.payment.amount_usei, result.quote.total_usei)
        self.assertEqual(result.payment.quote.rigor, "strict")

    def test_intent_rigor_floor_reaches_the_invoice(self) -> None:
        """An intent that raises rigor must raise the price too."""
        from tests.test_payments import VALID_SEI

        lax = pipeline.build(
            make_intent(rigor="lax"),
            self.config(rigor=Rigor.LAX, payee=VALID_SEI),
            write=False, store=False, sign=False,
        )
        strict = pipeline.build(
            make_intent(rigor="strict"),
            self.config(rigor=Rigor.LAX, payee=VALID_SEI),
            write=False, store=False, sign=False,
        )
        self.assertGreater(strict.payment.amount_usei, lax.payment.amount_usei)

    def test_extreme_rigor_demands_payment(self) -> None:
        config = self.config(rigor=Rigor.EXTREME)
        with self.assertRaises(PolicyError) as caught:
            pipeline.build(make_intent(), config, write=False, store=False)
        self.assertIn("payee", str(caught.exception).lower())

    def test_writes_land_on_disk(self) -> None:
        out = Path(self.tmp.name) / "out"
        result = pipeline.build(
            make_intent(), self.config(), write=True, store=False, out_dir=out
        )
        for artifact in result.artifacts:
            self.assertTrue((out / artifact.path).exists())
        self.assertTrue((out / "forge-manifest.json").exists())

    def test_manifest_verifies_against_what_was_written(self) -> None:
        from forge.canonical import loads
        from forge.signing.manifest import verify_integrity

        out = Path(self.tmp.name) / "out"
        result = pipeline.build(
            make_intent(), self.config(), write=True, store=False, out_dir=out
        )
        document = loads((out / "forge-manifest.json").read_bytes())
        self.assertEqual(verify_integrity(document, result.artifacts), [])

    def test_tampering_is_detected(self) -> None:
        from forge.canonical import loads
        from forge.signing.manifest import verify_integrity

        out = Path(self.tmp.name) / "out"
        result = pipeline.build(
            make_intent(), self.config(), write=True, store=False, out_dir=out
        )
        target = result.artifacts[0]
        tampered = [
            Artifact(path=a.path,
                     content=a.content + b"\n# injected\n" if a is target else a.content,
                     mode=a.mode, media_type=a.media_type)
            for a in result.artifacts
        ]
        document = loads((out / "forge-manifest.json").read_bytes())
        problems = verify_integrity(document, tampered)
        self.assertTrue(problems)
        self.assertIn("digest mismatch", " ".join(problems))

    def test_nondeterministic_generator_is_caught(self) -> None:
        """The strict double-build check must catch a generator that cheats."""
        import itertools

        from forge.generators import base

        counter = itertools.count()

        def sneaky(step, plan):
            return [Artifact(path="sneaky.py", content=f"n = {next(counter)}\n".encode())]

        base._REGISTRY["_sneaky_test"] = sneaky
        self.addCleanup(base._REGISTRY.pop, "_sneaky_test", None)

        document = make_intent()
        document["network"]["nodes"][0]["generator"] = "_sneaky_test"
        with self.assertRaises(IntegrityError) as caught:
            pipeline.build(
                document, self.config(rigor=Rigor.STRICT), write=False, store=False
            )
        self.assertIn("not reproducible", str(caught.exception))

    def test_unknown_generator_lists_the_available_ones(self) -> None:
        document = make_intent()
        document["network"]["nodes"][0]["generator"] = "cobol_emitter"
        with self.assertRaises(GeneratorError) as caught:
            pipeline.build(document, self.config(), write=False, store=False)
        self.assertIn("drf_endpoint", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
