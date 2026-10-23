"""Event contract and canonical JSON tests."""

import json
import unittest

from assay.errors import ValidationError
from assay.model import Event, canonical_bytes, normalize_timestamp


class CanonicalJsonTests(unittest.TestCase):
    def test_sorted_keys_and_unicode_are_stable(self):
        left = canonical_bytes({"b": 1, "a": "çğü"})
        right = canonical_bytes({"a": "çğü", "b": 1})
        self.assertEqual(left, right)
        self.assertIn("çğü".encode("utf-8"), left)

    def test_nested_order_does_not_change_bytes(self):
        left = canonical_bytes({"x": {"b": 2, "a": 1}})
        right = canonical_bytes({"x": {"a": 1, "b": 2}})
        self.assertEqual(left, right)


class TimestampTests(unittest.TestCase):
    def test_unix_seconds_become_utc(self):
        self.assertEqual(normalize_timestamp(0), "1970-01-01T00:00:00Z")

    def test_offset_is_normalized_to_utc(self):
        self.assertEqual(
            normalize_timestamp("2026-10-23T10:00:00+02:00"),
            "2026-10-23T08:00:00Z",
        )

    def test_naive_timestamp_is_refused(self):
        with self.assertRaises(ValidationError):
            normalize_timestamp("2026-10-23T10:00:00")

    def test_non_date_is_refused(self):
        with self.assertRaises(ValidationError):
            normalize_timestamp("yesterday")

    def test_out_of_range_epoch_is_refused(self):
        with self.assertRaises(ValidationError):
            normalize_timestamp(10 ** 30)


class EventTests(unittest.TestCase):
    def test_defaults_and_round_trip(self):
        event = Event.create("agent:a", "tool.call", ts="2026-10-23T09:00:00Z",
                             metadata={"amount": 10})
        value = event.to_dict()
        self.assertEqual(value["outcome"], "success")
        self.assertEqual(value["target"], "")
        self.assertEqual(len(value["id"]), 32)
        self.assertEqual(Event.from_dict(value), event)

    def test_empty_actor_is_refused(self):
        with self.assertRaises(ValidationError):
            Event.create("   ", "tool.call")

    def test_control_character_is_refused(self):
        with self.assertRaises(ValidationError):
            Event.create("agent\ninjected", "tool.call")

    def test_unknown_outcome_is_refused(self):
        with self.assertRaises(ValidationError):
            Event.create("agent:a", "tool.call", outcome="maybe")

    def test_non_object_metadata_is_refused(self):
        with self.assertRaises(ValidationError):
            Event.create("agent:a", "tool.call", metadata=["amount", 1])

    def test_nan_metadata_is_refused(self):
        with self.assertRaises(ValidationError):
            Event.create("agent:a", "tool.call", metadata={"amount": float("nan")})

    def test_unknown_stored_field_is_refused(self):
        value = Event.create("agent:a", "tool.call", ts="2026-10-23T09:00:00Z").to_dict()
        value["extra"] = True
        with self.assertRaises(ValidationError):
            Event.from_dict(value)

    def test_missing_stored_field_is_refused(self):
        value = Event.create("agent:a", "tool.call", ts="2026-10-23T09:00:00Z").to_dict()
        del value["outcome"]
        with self.assertRaises(ValidationError):
            Event.from_dict(value)

    def test_unsupported_schema_is_refused(self):
        value = Event.create("agent:a", "tool.call", ts="2026-10-23T09:00:00Z").to_dict()
        value["schema"] = 2
        with self.assertRaises(ValidationError):
            Event.from_dict(value)

    def test_policy_reference_digest_shape(self):
        with self.assertRaises(ValidationError):
            Event.create("agent:a", "tool.call", policy={"digest": "short"})
        event = Event.create("agent:a", "tool.call", policy={"name": "p", "digest": "a" * 64})
        self.assertEqual(event.policy["digest"], "a" * 64)

    def test_json_serializable_dict(self):
        event = Event.create("agent:a", "tool.call", metadata={"nested": {"x": [1, 2]}})
        self.assertEqual(json.loads(json.dumps(event.to_dict()))["metadata"]["nested"]["x"], [1, 2])


if __name__ == "__main__":
    unittest.main()
