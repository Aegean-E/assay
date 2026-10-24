"""End-to-end command-line tests through `main`, without spawning processes."""

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from assay.anchor import AnchorJournal
from assay.cli import main


class CliTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="assay-cli-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.ledger = self.root / "ledger.jsonl"
        self.policy = self.root / "policy.json"
        self.policy.write_text(json.dumps({
            "schema": 1,
            "name": "cli-policy",
            "default": "allow",
            "rules": [{"id": "shell", "action": "shell.*", "effect": "deny"}],
        }), encoding="utf-8")

    def _run(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([str(arg) for arg in args])
        return code, out.getvalue(), err.getvalue()

    def _record(self, action="files.read", **extra):
        args = ["record", "--ledger", self.ledger, "--actor", "agent:a", "--action", action,
                "--ts", "2026-10-23T09:00:00Z"]
        for key, value in extra.items():
            args.extend([f"--{key}", value])
        return self._run(*args)

    def test_record_and_verify(self):
        code, out, _ = self._record(metadata='{"amount": 10}')
        self.assertEqual(code, 0)
        self.assertIn("Recorded seq=0", out)
        code, out, _ = self._run("verify", "--ledger", self.ledger, "--json")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["records"], 1)

    def test_tampered_ledger_exits_one(self):
        self._record()
        lines = self.ledger.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[0])
        record["event"]["action"] = "files.delete"
        lines[0] = json.dumps(record, sort_keys=True, separators=(",", ":"))
        self.ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")
        code, out, _ = self._run("verify", "--ledger", self.ledger)
        self.assertEqual(code, 1)
        self.assertIn("Ledger FAILED", out)

    def test_record_attaches_policy_reference(self):
        code, _, _ = self._record(action="payments.transfer", policy=self.policy,
                                  metadata='{"amount": 5}')
        self.assertEqual(code, 0)
        event = json.loads(self.ledger.read_text(encoding="utf-8").splitlines()[0])["event"]
        self.assertEqual(event["policy"]["name"], "cli-policy")
        self.assertEqual(len(event["policy"]["digest"]), 64)

    def test_review_exit_codes(self):
        self._record("files.read")
        code, out, _ = self._run("review", "--ledger", self.ledger, "--policy", self.policy)
        self.assertEqual(code, 0)
        self.assertIn("findings: 0", out)
        self._record("shell.exec")
        code, out, _ = self._run("review", "--ledger", self.ledger, "--policy", self.policy,
                                 "--json")
        self.assertEqual(code, 1)
        payload = json.loads(out)
        self.assertEqual(len(payload["findings"]), 1)
        self.assertTrue(payload["ledger"]["verified"])

    def test_report_writes_markdown_and_json(self):
        self._record("files.read")
        self._record("shell.exec")
        md = self.root / "evidence.md"
        code, out, _ = self._run("report", "--ledger", self.ledger, "--policy", self.policy,
                                 "--out", md)
        self.assertEqual(code, 0)
        self.assertIn("Wrote", out)
        self.assertIn("Verdict: REVIEW", md.read_text(encoding="utf-8"))
        code, out, _ = self._run("report", "--ledger", self.ledger, "--policy", self.policy,
                                 "--format", "json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["summary"]["events"], 2)

    def test_ingest_generic(self):
        source = self.root / "events.jsonl"
        source.write_text(
            json.dumps({"actor": "agent:a", "action": "files.read", "metadata": {"n": 1}}) + "\n"
            + json.dumps({"agent": "agent:b", "tool": "shell.exec", "status": "error"}) + "\n",
            encoding="utf-8",
        )
        code, out, _ = self._run("ingest", "--ledger", self.ledger, "--file", source, "--json")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["recorded"], 2)
        self.assertEqual(len(self.ledger.read_text(encoding="utf-8").splitlines()), 2)

    def test_ingest_mcp(self):
        source = self.root / "mcp.jsonl"
        source.write_text(
            json.dumps({"method": "tools/call",
                        "params": {"name": "files.read", "arguments": {"path": "a.txt"}}}) + "\n"
            + json.dumps({"method": "tools/call",
                          "params": {"name": "shell.exec", "arguments": {}},
                          "result": {"isError": True}}) + "\n",
            encoding="utf-8",
        )
        code, _, _ = self._run("ingest", "--ledger", self.ledger, "--file", source,
                               "--format", "mcp", "--actor", "agent:mcp")
        self.assertEqual(code, 0)
        records = [json.loads(line) for line in self.ledger.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(records[0]["event"]["actor"], "agent:mcp")
        self.assertEqual(records[1]["event"]["outcome"], "error")

    def test_ingest_openai(self):
        source = self.root / "openai.jsonl"
        source.write_text(
            json.dumps({
                "id": "call_1",
                "type": "function",
                "function": {"name": "transact", "arguments": '{"amount": 100}'},
            }) + "\n",
            encoding="utf-8",
        )
        code, _, _ = self._run("ingest", "--ledger", self.ledger, "--file", source,
                               "--format", "openai", "--actor", "agent:openai")
        self.assertEqual(code, 0)
        record = json.loads(self.ledger.read_text(encoding="utf-8").splitlines()[0])["event"]
        self.assertEqual(record["actor"], "agent:openai")
        self.assertEqual(record["action"], "transact")
        self.assertEqual(record["metadata"]["amount"], 100)

    def test_ingest_langgraph(self):
        source = self.root / "langgraph.jsonl"
        source.write_text(
            json.dumps({
                "event": "on_tool_end",
                "name": "lookup_customer",
                "data": {"input": {"id": "c_42"}, "output": "VIP"},
                "actor": "agent:graph",
            }) + "\n",
            encoding="utf-8",
        )
        code, _, _ = self._run("ingest", "--ledger", self.ledger, "--file", source,
                               "--format", "langgraph")
        self.assertEqual(code, 0)
        record = json.loads(self.ledger.read_text(encoding="utf-8").splitlines()[0])["event"]
        self.assertEqual(record["actor"], "agent:graph")
        self.assertEqual(record["action"], "lookup_customer")
        self.assertEqual(record["metadata"]["id"], "c_42")

    def test_ingest_crewai(self):
        source = self.root / "crewai.jsonl"
        source.write_text(
            json.dumps({
                "agent": "Audit Specialist",
                "tool": "verify_balance",
                "tool_input": {"account": "acct_99"},
                "result": "verified",
            }) + "\n",
            encoding="utf-8",
        )
        code, _, _ = self._run("ingest", "--ledger", self.ledger, "--file", source,
                               "--format", "crewai")
        self.assertEqual(code, 0)
        record = json.loads(self.ledger.read_text(encoding="utf-8").splitlines()[0])["event"]
        self.assertEqual(record["actor"], "Audit Specialist")
        self.assertEqual(record["action"], "verify_balance")
        self.assertEqual(record["metadata"]["account"], "acct_99")

    def test_ingest_validates_before_writing(self):
        source = self.root / "events.jsonl"
        source.write_text(
            json.dumps({"actor": "agent:a", "action": "files.read"}) + "\n{}\n",
            encoding="utf-8",
        )
        code, _, err = self._run("ingest", "--ledger", self.ledger, "--file", source)
        self.assertEqual(code, 2)
        self.assertIn("Error:", err)
        self.assertFalse(self.ledger.exists())

    def test_usage_error_uses_triad(self):
        code, _, err = self._run("record")
        self.assertEqual(code, 2)
        self.assertIn("Error: Invalid command line:", err)
        self.assertIn("Why:", err)
        self.assertIn("Fix:", err)

    def test_missing_key_environment_variable(self):
        with patch.dict(os.environ, {}, clear=True):
            code, _, err = self._run("record", "--ledger", self.ledger, "--actor", "agent:a",
                                     "--action", "files.read",
                                     "--hmac-key-env", "ASSAY_TEST_MISSING_KEY")
        self.assertEqual(code, 2)
        self.assertIn("ASSAY_TEST_MISSING_KEY", err)
        self.assertFalse(self.ledger.exists())

    def test_signed_round_trip(self):
        key = "k" * 32
        with patch.dict(os.environ, {"ASSAY_TEST_KEY": key}):
            code, _, _ = self._run("record", "--ledger", self.ledger, "--actor", "agent:a",
                                   "--action", "files.read", "--hmac-key-env", "ASSAY_TEST_KEY")
            self.assertEqual(code, 0)
            code, out, _ = self._run("verify", "--ledger", self.ledger,
                                     "--hmac-key-env", "ASSAY_TEST_KEY", "--json")
            self.assertEqual(code, 0)
            self.assertTrue(json.loads(out)["key_checked"])
        code, out, _ = self._run("verify", "--ledger", self.ledger, "--json")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertTrue(payload["signed"])
        self.assertFalse(payload["key_checked"])

    def test_demo_writes_evidence(self):
        directory = self.root / "demo"
        code, out, _ = self._run("demo", "--out", directory, "--json")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertTrue(payload["verified"])
        self.assertEqual(payload["records"], 5)
        self.assertEqual(len(payload["findings"]), 2)
        self.assertTrue(Path(payload["evidence_markdown"]).is_file())
        self.assertTrue(Path(payload["evidence_json"]).is_file())
        pack = json.loads(Path(payload["evidence_json"]).read_text(encoding="utf-8"))
        self.assertEqual(pack["summary"]["policy_coverage"]["matching"], 5)

    def test_anchor_commits_to_the_ledger_head(self):
        self._record()
        self._record("shell.exec")
        anchors = self.root / "anchors.jsonl"
        code, out, _ = self._run("anchor", "--ledger", self.ledger, "--anchors", anchors)
        self.assertEqual(code, 0)
        self.assertIn("Anchored seq=1", out)
        state = AnchorJournal(anchors).inspect()
        self.assertTrue(state.verification.ok)
        self.assertEqual(state.records[0]["seq"], 1)
        self.assertEqual(state.records[0]["ledger"], "ledger.jsonl")
        last = json.loads(self.ledger.read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual(state.records[0]["head"], last["hash"])

    def test_anchor_refuses_a_broken_ledger(self):
        self._record()
        lines = self.ledger.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[0])
        record["event"]["action"] = "files.delete"
        lines[0] = json.dumps(record, sort_keys=True, separators=(",", ":"))
        self.ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")
        anchors = self.root / "anchors.jsonl"
        code, out, _ = self._run("anchor", "--ledger", self.ledger, "--anchors", anchors)
        self.assertEqual(code, 1)
        self.assertIn("Ledger FAILED", out)
        self.assertFalse(anchors.exists())

    def test_anchor_refuses_an_empty_ledger(self):
        self.ledger.write_text("", encoding="utf-8")
        anchors = self.root / "anchors.jsonl"
        code, _, err = self._run("anchor", "--ledger", self.ledger, "--anchors", anchors)
        self.assertEqual(code, 2)
        self.assertIn("no records to anchor", err)
        self.assertFalse(anchors.exists())

    def test_anchor_key_id_pairs_with_signing(self):
        anchors = self.root / "anchors.jsonl"
        key = "k" * 32
        with patch.dict(os.environ, {"ASSAY_TEST_KEY": key}):
            code, _, _ = self._run("record", "--ledger", self.ledger, "--actor", "agent:a",
                                   "--action", "files.read", "--hmac-key-env", "ASSAY_TEST_KEY")
            self.assertEqual(code, 0)
            code, _, err = self._run("anchor", "--ledger", self.ledger, "--anchors", anchors,
                                     "--hmac-key-env", "ASSAY_TEST_KEY")
            self.assertEqual(code, 2)
            self.assertIn("--key-id", err)
            code, _, err = self._run("anchor", "--ledger", self.ledger, "--anchors", anchors,
                                     "--hmac-key-env", "ASSAY_TEST_KEY", "--key-id", "ops-2026.10")
            self.assertEqual(code, 0)
        self.assertEqual(AnchorJournal(anchors).inspect().records[0]["key_id"], "ops-2026.10")
        other = self.root / "other.jsonl"
        code, _, err = self._run("anchor", "--ledger", self.ledger, "--anchors", other,
                                 "--key-id", "ops-2026.10")
        self.assertEqual(code, 2)
        self.assertIn("--hmac-key-env", err)

    def test_anchor_json_reports_the_record(self):
        self._record()
        anchors = self.root / "anchors.jsonl"
        code, out, _ = self._run("anchor", "--ledger", self.ledger, "--anchors", anchors, "--json")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["seq"], 0)
        self.assertEqual(len(payload["hash"]), 64)
        self.assertEqual(payload["schema"], 1)

    def test_verify_with_anchors_succeeds(self):
        self._record()
        self._record("shell.exec")
        anchors = self.root / "anchors.jsonl"
        code, _, _ = self._run("anchor", "--ledger", self.ledger, "--anchors", anchors)
        self.assertEqual(code, 0)
        code, out, _ = self._run("verify", "--ledger", self.ledger, "--anchors", anchors)
        self.assertEqual(code, 0)
        self.assertIn("Ledger OK", out)
        self.assertIn("Anchors OK: 1 anchor(s) verified", out)
        code, out, _ = self._run("verify", "--ledger", self.ledger, "--anchors", anchors, "--json")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["anchors"], 1)
        self.assertEqual(payload["errors"], [])

    def test_verify_anchors_detects_tail_truncation(self):
        self._record()
        self._record("shell.exec")
        self._record("payments.transfer")
        anchors = self.root / "anchors.jsonl"
        code, _, _ = self._run("anchor", "--ledger", self.ledger, "--anchors", anchors)
        self.assertEqual(code, 0)
        # Truncate to first 2 lines
        lines = self.ledger.read_text(encoding="utf-8").splitlines()
        self.ledger.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")
        # Without anchors, it passes because 2 records are a valid prefix
        code_without, _, _ = self._run("verify", "--ledger", self.ledger)
        self.assertEqual(code_without, 0)
        # With anchors, truncation is detected
        code, out, _ = self._run("verify", "--ledger", self.ledger, "--anchors", anchors)
        self.assertEqual(code, 1)
        self.assertIn("Ledger FAILED", out)
        self.assertIn("tail truncated", out)

    def test_verify_anchors_detects_rewritten_chain(self):
        self._record()
        anchors = self.root / "anchors.jsonl"
        code, _, _ = self._run("anchor", "--ledger", self.ledger, "--anchors", anchors)
        self.assertEqual(code, 0)
        # Rewrite the ledger with a different valid record at seq 0
        self.ledger.unlink()
        self._record("different.action")
        # Without anchors, the rewritten ledger alone verifies fine
        code_without, _, _ = self._run("verify", "--ledger", self.ledger)
        self.assertEqual(code_without, 0)
        # With anchors, the head mismatch is caught
        code, out, _ = self._run("verify", "--ledger", self.ledger, "--anchors", anchors)
        self.assertEqual(code, 1)
        self.assertIn("Ledger FAILED", out)
        self.assertIn("does not match ledger record hash", out)

    def test_verify_anchors_detects_tampered_anchor_journal(self):
        self._record()
        anchors = self.root / "anchors.jsonl"
        code, _, _ = self._run("anchor", "--ledger", self.ledger, "--anchors", anchors)
        self.assertEqual(code, 0)
        # Tamper with the anchor journal line
        data = json.loads(anchors.read_text(encoding="utf-8").splitlines()[0])
        data["head"] = "f" * 64
        anchors.write_text(json.dumps(data) + "\n", encoding="utf-8")
        code, out, _ = self._run("verify", "--ledger", self.ledger, "--anchors", anchors)
        self.assertEqual(code, 1)
        self.assertIn("Ledger FAILED", out)
        self.assertIn("Anchor journal error", out)

    def test_verify_missing_anchors_is_usage_error(self):
        self._record()
        code, _, err = self._run("verify", "--ledger", self.ledger,
                                 "--anchors", self.root / "missing.jsonl")
        self.assertEqual(code, 2)
        self.assertIn("does not exist", err)

    def test_missing_ledger_is_usage_error(self):
        code, _, err = self._run("verify", "--ledger", self.root / "missing.jsonl")
        self.assertEqual(code, 2)
        self.assertIn("does not exist", err)

    def test_policy_list_cli(self):
        code, out, _ = self._run("policy", "list")
        self.assertEqual(code, 0)
        self.assertIn("payments", out)
        self.assertIn("production_change", out)
        code, out, _ = self._run("policy", "list", "--json")
        self.assertEqual(code, 0)
        packs = json.loads(out)
        self.assertIsInstance(packs, list)
        self.assertTrue(any(p["pack"] == "payments" for p in packs))

    def test_policy_show_cli(self):
        code, out, _ = self._run("policy", "show", "payments")
        self.assertEqual(code, 0)
        self.assertIn("payments-guardrail", out)
        self.assertIn("Rules", out)
        code, out, _ = self._run("policy", "show", "payments", "--json")
        self.assertEqual(code, 0)
        policy_data = json.loads(out)
        self.assertEqual(policy_data["name"], "payments-guardrail")
        self.assertEqual(policy_data["schema"], 1)

    def test_review_with_policy_pack_reference(self):
        self._record(action="payments.transfer", metadata='{"amount": 15000}')
        code, out, _ = self._run("review", "--ledger", self.ledger, "--policy", "pack:payments")
        self.assertEqual(code, 1)
        self.assertIn("approve-high-transfers", out)


if __name__ == "__main__":
    unittest.main()
