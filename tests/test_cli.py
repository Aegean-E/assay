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

    def test_missing_ledger_is_usage_error(self):
        code, _, err = self._run("verify", "--ledger", self.root / "missing.jsonl")
        self.assertEqual(code, 2)
        self.assertIn("does not exist", err)


if __name__ == "__main__":
    unittest.main()
