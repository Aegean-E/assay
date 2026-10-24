"""Anchor record, journal chain and tamper detection tests."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from assay.anchor import AnchorJournal, anchor_hash, anchor_payload
from assay.errors import AnchorError, ValidationError
from assay.model import ZERO_HASH

CREATED = "2026-10-24T09:00:00Z"
HEAD_A = "a" * 64
HEAD_B = "b" * 64
HEAD_C = "c" * 64


def _append(journal, seq=0, head=HEAD_A, ledger="ledger.jsonl", key_id=None,
            created_at=CREATED):
    return journal.append(ledger=ledger, seq=seq, head=head, key_id=key_id,
                          created_at=created_at)


class AnchorPayloadTests(unittest.TestCase):
    def test_payload_is_canonical_json(self):
        payload = anchor_payload(
            schema=1, ledger="ledger.jsonl", seq=3, head=HEAD_A,
            created_at=CREATED, key_id="ops-2026.10", prev=ZERO_HASH,
        )
        self.assertEqual(
            payload,
            b'{"created_at":"2026-10-24T09:00:00Z","head":"' + HEAD_A.encode()
            + b'","key_id":"ops-2026.10","ledger":"ledger.jsonl","prev":"'
            + ZERO_HASH.encode() + b'","schema":1,"seq":3}',
        )

    def test_hash_covers_every_field(self):
        base = dict(schema=1, ledger="ledger.jsonl", seq=3, head=HEAD_A,
                    created_at=CREATED, key_id=None, prev=ZERO_HASH)
        digest = anchor_hash(**base)
        self.assertEqual(len(digest), 64)
        self.assertEqual(digest, anchor_hash(**base))
        self.assertNotEqual(digest, anchor_hash(**{**base, "seq": 4}))
        self.assertNotEqual(digest, anchor_hash(**{**base, "head": HEAD_B}))
        self.assertNotEqual(digest, anchor_hash(**{**base, "ledger": "other.jsonl"}))
        self.assertNotEqual(digest, anchor_hash(**{**base, "key_id": "k1"}))
        self.assertNotEqual(digest, anchor_hash(**{**base, "prev": HEAD_C}))

    def test_published_anchor_test_vector(self):
        head = "05e5bac80adac169419c1d1629545eace7af484da5c80c69be5e2fd42d1b8bcf"
        payload = anchor_payload(
            schema=1,
            ledger="ledger.jsonl",
            seq=0,
            head=head,
            created_at="2026-10-24T09:00:00Z",
            key_id="ops-2026.10",
            prev=ZERO_HASH,
        )
        self.assertEqual(
            payload,
            b'{"created_at":"2026-10-24T09:00:00Z","head":"05e5bac80adac169419c1d1629545eace7af484da5c80c69be5e2fd42d1b8bcf","key_id":"ops-2026.10","ledger":"ledger.jsonl","prev":"0000000000000000000000000000000000000000000000000000000000000000","schema":1,"seq":0}',
        )
        digest = anchor_hash(
            schema=1,
            ledger="ledger.jsonl",
            seq=0,
            head=head,
            created_at="2026-10-24T09:00:00Z",
            key_id="ops-2026.10",
            prev=ZERO_HASH,
        )
        self.assertEqual(digest, "c01d9febc847ea998dabeef20311b63ab1a90bb17d695c1fd3a53353eafe0143")


class AnchorJournalTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="assay-anchor-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.path = self.root / "anchors.jsonl"
        self.journal = AnchorJournal(self.path)

    def _rewrite(self, transform):
        records = [json.loads(line) for line in
                   self.path.read_text(encoding="utf-8").splitlines()]
        records = transform(records)
        self.path.write_text(
            "".join(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
                    for record in records),
            encoding="utf-8",
        )

    def test_append_creates_a_contiguous_anchor_chain(self):
        first = _append(self.journal, seq=0, head=HEAD_A)
        second = _append(self.journal, seq=2, head=HEAD_B)
        self.assertEqual(first["prev"], ZERO_HASH)
        self.assertEqual(second["prev"], first["hash"])
        state = self.journal.inspect()
        self.assertTrue(state.verification.ok)
        self.assertEqual(state.verification.anchors, 2)
        self.assertEqual(state.verification.head, second["hash"])
        self.assertEqual([record["seq"] for record in state.records], [0, 2])

    def test_duplicate_seq_is_allowed(self):
        _append(self.journal, seq=2, head=HEAD_A)
        _append(self.journal, seq=2, head=HEAD_A)
        state = self.journal.inspect()
        self.assertTrue(state.verification.ok)
        self.assertEqual(state.verification.anchors, 2)

    def test_seq_cannot_move_backwards(self):
        _append(self.journal, seq=2)
        with self.assertRaises(ValidationError):
            _append(self.journal, seq=1)

    def test_head_must_be_a_lowercase_sha256(self):
        with self.assertRaises(ValidationError):
            _append(self.journal, head="A" * 64)
        with self.assertRaises(ValidationError):
            _append(self.journal, head="abc")

    def test_negative_seq_is_refused(self):
        with self.assertRaises(ValidationError):
            _append(self.journal, seq=-1)

    def test_key_id_is_an_identifier_or_absent(self):
        self.assertEqual(_append(self.journal, key_id=None)["key_id"], None)
        stated = _append(self.journal, seq=1, key_id="ops-2026.10")
        self.assertEqual(stated["key_id"], "ops-2026.10")
        with self.assertRaises(ValidationError):
            _append(self.journal, seq=2, key_id="ops 2026")

    def test_created_at_is_normalized(self):
        record = _append(self.journal, created_at="2026-10-24T11:00:00+02:00")
        self.assertEqual(record["created_at"], CREATED)

    def test_tampered_anchor_is_detected(self):
        _append(self.journal, seq=0, head=HEAD_A)
        _append(self.journal, seq=1, head=HEAD_B)

        def tamper(records):
            records[0]["head"] = HEAD_C
            return records

        self._rewrite(tamper)
        state = self.journal.inspect()
        self.assertFalse(state.verification.ok)
        self.assertTrue(any("does not match its payload" in error
                            for error in state.verification.errors))

    def test_deleted_middle_anchor_is_detected(self):
        _append(self.journal, seq=0, head=HEAD_A)
        _append(self.journal, seq=1, head=HEAD_B)
        _append(self.journal, seq=2, head=HEAD_C)

        def drop_middle(records):
            return [records[0], records[2]]

        self._rewrite(drop_middle)
        state = self.journal.inspect()
        self.assertFalse(state.verification.ok)
        self.assertTrue(any("prev does not match" in error
                            for error in state.verification.errors))

    def test_unknown_field_is_refused(self):
        _append(self.journal)

        def add_field(records):
            records[0]["note"] = "extra"
            return records

        self._rewrite(add_field)
        state = self.journal.inspect()
        self.assertFalse(state.verification.ok)
        self.assertTrue(any("unknown field" in error
                            for error in state.verification.errors))

    def test_unsupported_schema_is_refused(self):
        _append(self.journal)

        def bump_schema(records):
            records[0]["schema"] = 2
            return records

        self._rewrite(bump_schema)
        state = self.journal.inspect()
        self.assertFalse(state.verification.ok)
        self.assertTrue(any("schema" in error for error in state.verification.errors))

    def test_corrupt_tail_refuses_append(self):
        self.path.write_text("not json\n", encoding="utf-8")
        with self.assertRaises(AnchorError):
            _append(self.journal)

    def test_missing_journal_raises(self):
        with self.assertRaises(AnchorError):
            self.journal.inspect()


if __name__ == "__main__":
    unittest.main()
