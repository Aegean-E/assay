"""Evidence pack assembly and rendering tests."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from assay.ledger import Ledger
from assay.model import Event
from assay.policy import parse_policy
from assay.report import build_pack, render_markdown, write_report


def _event(action, **metadata):
    return Event.create("agent:a", action, ts="2026-10-23T09:00:00Z",
                        target=metadata.pop("target", ""), metadata=metadata)


def _policy(rules=None):
    return parse_policy({
        "schema": 1,
        "name": "review-policy",
        "default": "allow",
        "rules": rules or [],
    })


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="assay-report-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.path = self.root / "ledger.jsonl"

    def _state(self, actions):
        ledger = Ledger(self.path)
        for action in actions:
            ledger.append(_event(action))
        return ledger.inspect()

    def test_review_verdict_and_markdown(self):
        state = self._state(["files.read", "shell.exec", "payments.transfer"])
        policy = _policy([{"id": "shell", "action": "shell.*", "effect": "deny"}])
        pack = build_pack(str(self.path), state, policy)
        self.assertEqual(pack["verdict"], "REVIEW")
        self.assertEqual(pack["summary"]["events"], 3)
        self.assertEqual(pack["summary"]["findings"]["total"], 1)
        self.assertEqual(pack["summary"]["findings"]["denied"], 1)
        self.assertEqual(len(pack["events"]), 3)
        self.assertEqual(pack["policy"]["document"]["name"], "review-policy")
        markdown = render_markdown(pack)
        self.assertIn("Verdict: REVIEW", markdown)
        self.assertIn("shell.exec", markdown)
        self.assertIn("Chain verified | yes", markdown)
        self.assertIn("Policy rules", markdown)
        self.assertIn("shell.*", markdown)
        self.assertIn(pack["ledger"]["head"], markdown)
        json.dumps(pack)

    def test_pass_verdict_without_findings(self):
        state = self._state(["files.read", "crm.export"])
        pack = build_pack(str(self.path), state, _policy())
        self.assertEqual(pack["verdict"], "PASS")
        self.assertIn("No policy findings", render_markdown(pack))

    def test_fail_verdict_on_broken_chain(self):
        self._state(["files.read"])
        lines = self.path.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[0])
        record["event"]["actor"] = "agent:tampered"
        lines[0] = json.dumps(record, sort_keys=True, separators=(",", ":"))
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        state = Ledger(self.path).inspect()
        pack = build_pack(str(self.path), state, _policy())
        self.assertEqual(pack["verdict"], "FAIL")
        self.assertIn("Chain errors", render_markdown(pack))

    def test_no_policy_is_allowed(self):
        state = self._state(["files.read"])
        pack = build_pack(str(self.path), state, None)
        self.assertIsNone(pack["policy"])
        self.assertIn("not supplied", render_markdown(pack))

    def test_markdown_escapes_table_cells(self):
        ledger = Ledger(self.path)
        ledger.append(Event.create("agent:a", "files.read", target="a|b",
                                   ts="2026-10-23T09:00:00Z"))
        pack = build_pack(str(self.path), ledger.inspect(), None)
        self.assertIn("a\\|b", render_markdown(pack))

    def test_write_json_and_markdown(self):
        state = self._state(["files.read"])
        pack = build_pack(str(self.path), state, _policy())
        json_path = self.root / "evidence.json"
        md_path = self.root / "evidence.md"
        write_report(pack, json_path, "json")
        write_report(pack, md_path, "md")
        self.assertEqual(json.loads(json_path.read_text(encoding="utf-8"))["verdict"], "PASS")
        self.assertIn("# Assay Evidence Pack", md_path.read_text(encoding="utf-8"))

    def test_unknown_format_is_refused(self):
        state = self._state(["files.read"])
        with self.assertRaises(ValueError):
            write_report(build_pack(str(self.path), state, None), self.root / "x.txt", "txt")


if __name__ == "__main__":
    unittest.main()
