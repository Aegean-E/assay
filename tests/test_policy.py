"""Policy parsing, matching and finding tests."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from assay.errors import ValidationError
from assay.model import Event
from assay.policy import drift_findings, load_policy, parse_policy, review_events


def _event(action="payments.transfer", **metadata):
    return Event.create("agent:a", action, ts="2026-10-23T09:00:00Z", metadata=metadata)


def _document(**overrides):
    document = {
        "schema": 1,
        "name": "test-policy",
        "default": "allow",
        "rules": [],
    }
    document.update(overrides)
    return document


class PolicyEvaluationTests(unittest.TestCase):
    def test_default_allow(self):
        policy = parse_policy(_document())
        self.assertEqual(policy.evaluate(_event()).effect, "allow")

    def test_deny_glob(self):
        policy = parse_policy(_document(rules=[
            {"id": "shell", "action": "shell.*", "effect": "deny"},
        ]))
        self.assertEqual(policy.evaluate(_event("shell.exec")).effect, "deny")
        self.assertEqual(policy.evaluate(_event("files.read")).effect, "allow")

    def test_require_approval(self):
        policy = parse_policy(_document(rules=[
            {"id": "approve", "action": "payments.*", "effect": "require_approval"},
        ]))
        self.assertEqual(policy.evaluate(_event()).effect, "require_approval")
        self.assertIsNotNone(policy.review(_event()))
        self.assertIsNone(policy.review(_event(approved_by="controller@example")))

    def test_amount_over_threshold(self):
        policy = parse_policy(_document(rules=[
            {"id": "cap", "action": "payments.*", "effect": "deny", "amount_over": 10000},
        ]))
        self.assertEqual(policy.evaluate(_event(amount=10001)).effect, "deny")
        self.assertEqual(policy.evaluate(_event(amount=10000)).effect, "allow")
        self.assertIn("exceeds 10000", policy.evaluate(_event(amount=10001)).reason)

    def test_amount_under_threshold(self):
        policy = parse_policy(_document(rules=[
            {"id": "floor", "action": "payments.*", "effect": "deny", "amount_under": 10},
        ]))
        self.assertEqual(policy.evaluate(_event(amount=9)).effect, "deny")
        self.assertEqual(policy.evaluate(_event(amount=10)).effect, "allow")

    def test_amount_band(self):
        policy = parse_policy(_document(rules=[
            {"id": "band", "action": "payments.*", "effect": "deny",
             "amount_under": 10, "amount_over": 100},
        ]))
        self.assertEqual(policy.evaluate(_event(amount=9)).effect, "deny")
        self.assertEqual(policy.evaluate(_event(amount=50)).effect, "allow")
        self.assertEqual(policy.evaluate(_event(amount=101)).effect, "deny")
        self.assertIn("outside", policy.evaluate(_event(amount=101)).reason)

    def test_unverifiable_amount_is_denied(self):
        policy = parse_policy(_document(rules=[
            {"id": "cap", "action": "payments.*", "effect": "deny", "amount_over": 10},
        ]))
        decision = policy.evaluate(_event())
        self.assertEqual(decision.effect, "deny")
        self.assertIn("missing or not numeric", decision.reason)
        decision = policy.evaluate(_event(amount="many"))
        self.assertEqual(decision.effect, "deny")

    def test_metadata_condition(self):
        policy = parse_policy(_document(rules=[
            {"id": "prod", "action": "db.*", "effect": "deny", "metadata": {"env": "prod"}},
        ]))
        self.assertEqual(policy.evaluate(_event("db.write", env="prod")).effect, "deny")
        self.assertEqual(policy.evaluate(_event("db.write", env="dev")).effect, "allow")

    def test_first_match_wins(self):
        policy = parse_policy(_document(rules=[
            {"id": "first", "action": "payments.*", "effect": "deny"},
            {"id": "second", "action": "payments.*", "effect": "require_approval"},
        ]))
        self.assertEqual(policy.evaluate(_event()).rule_id, "first")

    def test_default_deny(self):
        policy = parse_policy(_document(default="deny"))
        self.assertEqual(policy.evaluate(_event()).effect, "deny")
        self.assertIsNotNone(policy.review(_event()))

    def test_digest_stable_and_reference(self):
        first = parse_policy(_document(rules=[
            {"id": "shell", "action": "shell.*", "effect": "deny"},
        ]))
        second = parse_policy(first.to_dict())
        self.assertEqual(first.digest, second.digest)
        self.assertEqual(first.reference(), {"name": "test-policy", "digest": first.digest})

    def test_rule_without_amount_condition_matches(self):
        policy = parse_policy(_document(rules=[
            {"id": "read", "action": "files.read", "effect": "deny"},
        ]))
        self.assertEqual(policy.evaluate(_event("files.read")).effect, "deny")


class PolicyValidationTests(unittest.TestCase):
    def test_invalid_documents_are_refused(self):
        cases = {
            "not an object": [],
            "missing name": {"schema": 1},
            "bad schema": {"schema": 2, "name": "p"},
            "bad default": _document(default="maybe"),
            "rules not a list": _document(rules={}),
            "duplicate ids": _document(rules=[
                {"id": "x", "action": "a", "effect": "deny"},
                {"id": "x", "action": "b", "effect": "allow"},
            ]),
            "unknown rule field": _document(rules=[
                {"id": "x", "action": "a", "effect": "deny", "amount": 1},
            ]),
            "bad effect": _document(rules=[
                {"id": "x", "action": "a", "effect": "block"},
            ]),
            "negative threshold": _document(rules=[
                {"id": "x", "action": "a", "effect": "deny", "amount_over": -1},
            ]),
            "inverted band": _document(rules=[
                {"id": "x", "action": "a", "effect": "deny",
                 "amount_under": 10, "amount_over": 5},
            ]),
            "metadata not object": _document(rules=[
                {"id": "x", "action": "a", "effect": "deny", "metadata": []},
            ]),
        }
        for label, document in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(ValidationError):
                    parse_policy(document)

    def test_load_policy(self):
        root = Path(tempfile.mkdtemp(prefix="assay-policy-"))
        self.addCleanup(shutil.rmtree, root, True)
        path = root / "policy.json"
        path.write_text(json.dumps(_document()), encoding="utf-8")
        self.assertEqual(load_policy(path).name, "test-policy")
        path.write_text("{bad", encoding="utf-8")
        with self.assertRaises(ValidationError):
            load_policy(path)
        with self.assertRaises(ValidationError):
            load_policy(root / "missing.json")


class PolicyReviewTests(unittest.TestCase):
    def _records(self):
        policy = parse_policy(_document(rules=[
            {"id": "shell", "action": "shell.*", "effect": "deny"},
        ]))
        records = []
        for index, action in enumerate(("files.read", "shell.exec")):
            event = Event.create("agent:a", action, ts="2026-10-23T09:00:00Z")
            records.append({"seq": index, "event": event.to_dict()})
        return policy, records

    def test_review_events_attaches_sequence(self):
        policy, records = self._records()
        findings = review_events(policy, records)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].seq, 1)
        self.assertEqual(findings[0].rule_id, "shell")

    def test_drift_findings(self):
        policy, records = self._records()
        records[0]["event"]["policy"] = {"name": "old", "digest": "a" * 64}
        findings = drift_findings(policy, records)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].effect, "policy_drift")
        self.assertEqual(findings[0].seq, 0)

    def test_no_findings_for_compliant_records(self):
        policy = parse_policy(_document())
        event = Event.create("agent:a", "files.read", ts="2026-10-23T09:00:00Z")
        self.assertEqual(review_events(policy, [{"seq": 0, "event": event.to_dict()}]), [])


if __name__ == "__main__":
    unittest.main()
