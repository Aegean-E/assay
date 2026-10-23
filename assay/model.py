"""Event contract and canonical serialization for the evidence ledger."""

from __future__ import annotations

import json
import math
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional

from .errors import ValidationError

SCHEMA_VERSION = 1
ZERO_HASH = "0" * 64
OUTCOMES = ("success", "error", "denied", "pending")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_EVENT_FIELDS = frozenset(
    {"schema", "id", "ts", "actor", "action", "outcome", "target", "metadata", "policy"}
)


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    """Deterministic UTF-8 JSON used for every digest in the ledger."""
    try:
        text = json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValidationError(
            f"The document is not canonical JSON: {exc}.",
            "a digest must be identical on every host, so only finite JSON values are allowed.",
            "remove non-JSON values such as NaN, bytes or custom objects.",
        ) from exc
    return text.encode("utf-8")


def utc_now() -> str:
    """Current UTC time in the ISO-8601 form stored in events."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def normalize_timestamp(value: Any) -> str:
    """Accept an ISO-8601 string or Unix seconds and return a UTC ISO-8601 string."""
    if isinstance(value, bool):
        raise ValidationError(
            "A timestamp cannot be a boolean.",
            "booleans are not dates.",
            "pass an ISO-8601 string or Unix seconds.",
        )
    if isinstance(value, (int, float)):
        if not math.isfinite(float(value)):
            raise ValidationError(
                "The timestamp is not finite.",
                "a non-finite epoch cannot be represented as a date.",
                "pass a finite number of Unix seconds.",
            )
        try:
            parsed = datetime.fromtimestamp(float(value), timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise ValidationError(
                "The timestamp is outside the supported date range.",
                "a date beyond the platform's range cannot be compared or rendered.",
                "pass Unix seconds between year 1 and year 9999.",
            ) from exc
        return parsed.isoformat(timespec="seconds").replace("+00:00", "Z")
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(
            "The timestamp must be a non-empty ISO-8601 string or Unix seconds.",
            "events need an explicit time so a report can order and date the evidence.",
            "pass e.g. --ts 2026-10-23T16:30:00Z.",
        )
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(
            f"'{text[:64]}' is not ISO-8601.",
            "a free-form timestamp cannot be compared across systems.",
            "pass e.g. 2026-10-23T16:30:00Z.",
        ) from exc
    if parsed.tzinfo is None:
        raise ValidationError(
            f"'{text[:64]}' has no timezone.",
            "an unzoned timestamp is ambiguous across hosts and audit regions.",
            "append Z for UTC or a numeric offset such as +02:00.",
        )
    return parsed.astimezone(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def _text(value: Any, name: str, limit: int, required: bool = True) -> str:
    if not isinstance(value, str):
        raise ValidationError(
            f"Event field '{name}' must be a string.",
            "a type change would alter the hashed evidence.",
            f"pass '{name}' as text.",
        )
    text = value.strip()
    if required and not text:
        raise ValidationError(
            f"Event field '{name}' is empty.",
            "an unnamed actor or action cannot be audited.",
            f"pass a non-empty '{name}'.",
        )
    if len(text) > limit:
        raise ValidationError(
            f"Event field '{name}' exceeds {limit} characters.",
            "oversized fields make evidence hard to review and store.",
            f"shorten '{name}'.",
        )
    if any(ord(char) < 32 for char in text):
        raise ValidationError(
            f"Event field '{name}' contains a control character.",
            "control characters break line-oriented ledgers and reports.",
            f"remove newlines and control characters from '{name}'.",
        )
    return text


def _metadata(value: Any) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValidationError(
            "Event metadata must be a JSON object.",
            "a list or scalar cannot carry named evidence fields.",
            "pass metadata as an object such as {\"amount\": 2500}.",
        )
    canonical_bytes(value)
    return dict(value)


def _policy_ref(value: Any) -> Optional[Dict[str, str]]:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) - {"name", "digest"}:
        raise ValidationError(
            "The policy reference must be an object with optional 'name' and 'digest'.",
            "the reference records which policy was active when the event happened.",
            "pass {\"name\": \"treasury\", \"digest\": \"<sha256>\"}.",
        )
    reference: Dict[str, str] = {}
    if "name" in value:
        reference["name"] = _text(value["name"], "policy.name", 120)
    if "digest" in value:
        digest = _text(value["digest"], "policy.digest", 64).lower()
        if not _HEX_64.match(digest):
            raise ValidationError(
                "The policy digest must be 64 hexadecimal characters.",
                "the digest is compared byte-for-byte with the policy file.",
                "use the sha256 value printed by `assay review` or `assay record`.",
            )
        reference["digest"] = digest
    return reference or None


@dataclass(frozen=True)
class Event:
    """One agent action, normalized and validated before hashing."""

    actor: str
    action: str
    ts: str = field(default_factory=utc_now)
    outcome: str = "success"
    target: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    policy: Optional[Dict[str, str]] = None
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    schema: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "actor", _text(self.actor, "actor", 200))
        object.__setattr__(self, "action", _text(self.action, "action", 200))
        object.__setattr__(self, "ts", normalize_timestamp(self.ts))
        if self.outcome not in OUTCOMES:
            raise ValidationError(
                f"Unknown outcome '{self.outcome}'.",
                f"the contract allows: {', '.join(OUTCOMES)}.",
                "pick one of the listed outcomes.",
            )
        object.__setattr__(self, "target", _text(self.target, "target", 500, required=False))
        object.__setattr__(self, "metadata", _metadata(self.metadata))
        object.__setattr__(self, "policy", _policy_ref(self.policy))
        object.__setattr__(self, "id", _text(self.id, "id", 64).lower())
        if isinstance(self.schema, bool) or not isinstance(self.schema, int) \
                or self.schema != SCHEMA_VERSION:
            raise ValidationError(
                f"Unsupported event schema {self.schema}.",
                f"this build writes schema {SCHEMA_VERSION}.",
                "upgrade Assay or convert the event with the matching schema version.",
            )

    @classmethod
    def create(cls, actor: str, action: str, **values: Any) -> "Event":
        """Build an event from CLI or adapter input with the documented defaults."""
        return cls(actor=actor, action=action, **values)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Event":
        """Parse a stored event, refusing unknown fields instead of silently dropping them."""
        if not isinstance(value, Mapping):
            raise ValidationError(
                "An event must be a JSON object.",
                "the ledger stores one object per record.",
                "fix the producer to emit objects.",
            )
        unknown = set(value) - _EVENT_FIELDS
        if unknown:
            raise ValidationError(
                f"Unknown event field(s): {', '.join(sorted(unknown))}.",
                "unknown fields would be excluded from the digest and silently unverifiable.",
                "remove them, or record the data under 'metadata'.",
            )
        missing = [name for name in ("schema", "id", "ts", "actor", "action", "outcome") if name not in value]
        if missing:
            raise ValidationError(
                f"Missing event field(s): {', '.join(missing)}.",
                "every record must carry the full versioned contract.",
                "add the missing fields or upgrade the producer.",
            )
        return cls(
            schema=value["schema"],
            id=value["id"],
            ts=value["ts"],
            actor=value["actor"],
            action=value["action"],
            outcome=value["outcome"],
            target=value.get("target", ""),
            metadata=value.get("metadata", {}),
            policy=value.get("policy"),
        )

    def to_dict(self) -> Dict[str, Any]:
        """The canonical stored form; `None` fields are omitted."""
        value: Dict[str, Any] = {
            "schema": self.schema,
            "id": self.id,
            "ts": self.ts,
            "actor": self.actor,
            "action": self.action,
            "outcome": self.outcome,
            "target": self.target,
            "metadata": self.metadata,
        }
        if self.policy is not None:
            value["policy"] = self.policy
        return value
