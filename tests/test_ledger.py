"""Hash chain, tamper detection and signing tests."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from assay.errors import LedgerError
from assay.ledger import Ledger, record_hash, record_mac
from assay.model import Event, ZERO_HASH
from assay.storage import last_nonempty_line


def _event(number: int) -> Event:
    return Event.create("agent:a", f"tool.{number}", ts="2026-10-23T09:00:00Z",
                        metadata={"number": number})


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="assay-ledger-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.path = self.root / "ledger.jsonl"

    def _write_events(self, count=3, key=None):
        ledger = Ledger(self.path, key)
        return [ledger.append(_event(index)) for index in range(count)]

    def test_append_creates_a_contiguous_chain(self):
        envelopes = self._write_events(3)
        state = Ledger(self.path).inspect()
        self.assertTrue(state.verification.ok)
        self.assertEqual(state.verification.records, 3)
        self.assertEqual([record["seq"] for record in state.records], [0, 1, 2])
        self.assertEqual(state.records[0]["prev"], ZERO_HASH)
        self.assertEqual(state.verification.head, envelopes[-1]["hash"])
        self.assertEqual(len(self.path.read_text(encoding="utf-8").splitlines()), 3)

    def test_tail_reads_a_long_last_line(self):
        content = "one\ntwo\n" + ("x" * 70000) + "\n"
        self.path.write_text(content, encoding="utf-8")
        self.assertEqual(last_nonempty_line(self.path), "x" * 70000)

    def test_append_after_a_long_record(self):
        ledger = Ledger(self.path)
        ledger.append(Event.create("agent:a", "files.read", metadata={"blob": "x" * 70000},
                                   ts="2026-10-23T09:00:00Z"))
        ledger.append(_event(2))
        state = ledger.inspect()
        self.assertTrue(state.verification.ok)
        self.assertEqual(state.verification.records, 2)

    def test_hashes_are_deterministic(self):
        event = _event(1).to_dict()
        self.assertEqual(record_hash(0, ZERO_HASH, event), record_hash(0, ZERO_HASH, event))
        self.assertNotEqual(record_hash(0, ZERO_HASH, event), record_hash(1, ZERO_HASH, event))

    def test_published_test_vector(self):
        event = {
            "schema": 1,
            "id": "0123456789abcdef0123456789abcdef",
            "ts": "2026-10-23T09:00:00Z",
            "actor": "agent:treasury-bot",
            "action": "payments.transfer",
            "outcome": "success",
            "target": "acct:vendor-17",
            "metadata": {"amount": 4200, "approved_by": "controller@acme.example"},
        }
        key = b"0123456789abcdef0123456789abcdef"
        self.assertEqual(
            record_hash(0, ZERO_HASH, event),
            "05e5bac80adac169419c1d1629545eace7af484da5c80c69be5e2fd42d1b8bcf",
        )
        self.assertEqual(
            record_mac(key, 0, ZERO_HASH, event),
            "83005ac693ef1c086b7efa336be63fbfc11fe8a16ae50948b4714d89f8ce0272",
        )

    def test_tampered_event_is_detected(self):
        self._write_events(2)
        lines = self.path.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[0])
        record["event"]["action"] = "tool.tampered"
        lines[0] = json.dumps(record, sort_keys=True, separators=(",", ":"))
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        state = Ledger(self.path).inspect()
        self.assertFalse(state.verification.ok)
        self.assertTrue(any("hash mismatch" in error for error in state.verification.errors))

    def test_deleted_middle_is_detected(self):
        self._write_events(3)
        lines = self.path.read_text(encoding="utf-8").splitlines()
        self.path.write_text(lines[0] + "\n" + lines[2] + "\n", encoding="utf-8")
        state = Ledger(self.path).inspect()
        self.assertFalse(state.verification.ok)
        self.assertTrue(any("prev does not match" in error for error in state.verification.errors))

    def test_malformed_line_is_detected(self):
        self._write_events(1)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write("not json\n")
        state = Ledger(self.path).inspect()
        self.assertFalse(state.verification.ok)
        self.assertTrue(any("invalid JSON" in error for error in state.verification.errors))

    def test_signed_chain_verifies_with_key(self):
        key = b"k" * 32
        self._write_events(2, key)
        state = Ledger(self.path, key).inspect()
        self.assertTrue(state.verification.ok)
        self.assertTrue(state.verification.signed)
        self.assertTrue(state.verification.key_checked)

    def test_signed_chain_without_key_is_flagged_unchecked(self):
        self._write_events(2, b"k" * 32)
        state = Ledger(self.path).inspect()
        self.assertTrue(state.verification.ok)
        self.assertTrue(state.verification.signed)
        self.assertFalse(state.verification.key_checked)

    def test_wrong_key_is_detected(self):
        self._write_events(2, b"k" * 32)
        state = Ledger(self.path, b"x" * 32).inspect()
        self.assertFalse(state.verification.ok)
        self.assertTrue(any("HMAC mismatch" in error for error in state.verification.errors))

    def test_unsigned_chain_fails_when_a_key_is_supplied(self):
        self._write_events(1)
        state = Ledger(self.path, b"k" * 32).inspect()
        self.assertFalse(state.verification.ok)
        self.assertTrue(any("not HMAC-signed" in error for error in state.verification.errors))

    def test_mixed_signing_is_detected(self):
        self._write_events(1, b"k" * 32)
        Ledger(self.path).append(_event(2))
        state = Ledger(self.path).inspect()
        self.assertFalse(state.verification.ok)
        self.assertTrue(any("mixes signed" in error for error in state.verification.errors))

    def test_append_refuses_a_corrupt_tail(self):
        self.path.write_text("not json\n", encoding="utf-8")
        with self.assertRaises(LedgerError):
            Ledger(self.path).append(_event(1))

    def test_append_refuses_a_tail_with_an_invalid_hash(self):
        self.path.write_text(json.dumps({"seq": 0, "hash": "x"}) + "\n", encoding="utf-8")
        with self.assertRaises(LedgerError):
            Ledger(self.path).append(_event(1))

    def test_append_refuses_a_negative_tail_seq(self):
        self.path.write_text(json.dumps({"seq": -1, "hash": ZERO_HASH}) + "\n",
                             encoding="utf-8")
        with self.assertRaises(LedgerError):
            Ledger(self.path).append(_event(1))

    def test_missing_ledger_raises(self):
        with self.assertRaises(LedgerError):
            Ledger(self.path).inspect()


if __name__ == "__main__":
    unittest.main()
