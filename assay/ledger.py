"""Append-only hash-chained ledger with optional HMAC signing."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .errors import LedgerError, ValidationError
from .model import Event, ZERO_HASH, canonical_bytes
from .storage import append_line, last_nonempty_line, read_lines

ENVELOPE_FIELDS = frozenset({"seq", "prev", "event", "hash", "mac"})


def record_payload(seq: int, prev: str, event: Mapping[str, Any]) -> bytes:
    """The exact bytes a record hash covers; documented in docs/SECURITY.md."""
    return canonical_bytes({"seq": seq, "prev": prev, "event": event})


def record_hash(seq: int, prev: str, event: Mapping[str, Any]) -> str:
    """SHA-256 over the canonical record payload."""
    return hashlib.sha256(record_payload(seq, prev, event)).hexdigest()


def record_mac(key: bytes, seq: int, prev: str, event: Mapping[str, Any]) -> str:
    """HMAC-SHA256 over the same payload, keyed by a secret the verifier holds."""
    return hmac.new(key, record_payload(seq, prev, event), hashlib.sha256).hexdigest()


def _json_line(envelope: Mapping[str, Any]) -> str:
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class Verification:
    """The outcome of walking the whole chain once."""

    ok: bool
    records: int
    head: str
    signed: bool
    key_checked: bool
    errors: Tuple[str, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "records": self.records,
            "head": self.head,
            "signed": self.signed,
            "key_checked": self.key_checked,
            "errors": list(self.errors),
        }


@dataclass(frozen=True)
class LedgerState:
    """Records and their verification, read in one pass."""

    records: Tuple[Dict[str, Any], ...]
    verification: Verification


class Ledger:
    """Persist events in a JSONL file whose every record commits to its predecessor."""

    def __init__(self, path: Path, key: Optional[bytes] = None) -> None:
        self.path = Path(path)
        self.key = key

    def append(self, event: Event) -> Dict[str, Any]:
        """Append one event and return the stored envelope."""
        seq, prev = self._tail()
        value = event.to_dict()
        envelope: Dict[str, Any] = {
            "seq": seq,
            "prev": prev,
            "event": value,
            "hash": record_hash(seq, prev, value),
        }
        if self.key is not None:
            envelope["mac"] = record_mac(self.key, seq, prev, value)
        try:
            append_line(self.path, _json_line(envelope))
        except OSError as exc:
            raise LedgerError(
                f"The ledger could not be appended: {exc}.",
                "the evidence file must accept a durable write before the action is confirmed.",
                "check the path, free space and permissions, then retry.",
            ) from exc
        return envelope

    def inspect(self) -> LedgerState:
        """Read and verify every record; malformed or tampered records become findings."""
        if not self.path.is_file():
            raise LedgerError(
                f"The ledger '{self.path}' does not exist.",
                "verification needs the evidence file it should attest.",
                "record an event first, or pass --ledger with the correct path.",
            )
        records: List[Dict[str, Any]] = []
        errors: List[str] = []
        expected_prev = ZERO_HASH
        any_mac = False
        all_mac = True
        try:
            lines = list(read_lines(self.path))
        except (OSError, UnicodeError) as exc:
            raise LedgerError(
                f"The ledger could not be read: {exc}.",
                "an unreadable evidence file cannot be verified.",
                "check the path and permissions, then retry.",
            ) from exc
        for number, line in enumerate(lines, start=1):
            if not line.strip():
                errors.append(f"line {number}: blank line")
                all_mac = False
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(f"line {number}: invalid JSON ({exc.msg})")
                all_mac = False
                continue
            if not isinstance(value, dict):
                errors.append(f"line {number}: record is not an object")
                all_mac = False
                continue
            unknown = set(value) - ENVELOPE_FIELDS
            if unknown:
                errors.append(f"line {number}: unknown field(s) {', '.join(sorted(unknown))}")
            seq = value.get("seq")
            if isinstance(seq, bool) or not isinstance(seq, int):
                errors.append(f"line {number}: seq is not an integer")
                all_mac = False
                continue
            if seq != len(records):
                errors.append(f"line {number}: seq {seq} does not follow {len(records)}")
            prev = value.get("prev")
            if not isinstance(prev, str) or len(prev) != 64:
                errors.append(f"line {number}: prev is not a 64-character digest")
                all_mac = False
                continue
            if prev != expected_prev:
                errors.append(f"line {number}: prev does not match the previous record")
            try:
                event = Event.from_dict(value.get("event", {}))
            except ValidationError as exc:
                errors.append(f"line {number}: event is invalid ({exc.message})")
                all_mac = False
                continue
            stored_hash = value.get("hash")
            computed = record_hash(seq, prev, event.to_dict())
            if stored_hash != computed:
                errors.append(f"line {number}: hash mismatch")
            mac = value.get("mac")
            if mac is not None:
                any_mac = True
                if not isinstance(mac, str):
                    errors.append(f"line {number}: mac is not text")
                    all_mac = False
                elif self.key is not None:
                    expected_mac = record_mac(self.key, seq, prev, event.to_dict())
                    if not hmac.compare_digest(mac, expected_mac):
                        errors.append(f"line {number}: HMAC mismatch")
            else:
                all_mac = False
                if self.key is not None:
                    errors.append(f"line {number}: record is not HMAC-signed")
            records.append(value)
            expected_prev = stored_hash if isinstance(stored_hash, str) else computed
        signed = bool(records) and all_mac
        if any_mac and not all_mac:
            errors.append("the ledger mixes signed and unsigned records")
        head = records[-1].get("hash") if records else ZERO_HASH
        verification = Verification(
            ok=not errors,
            records=len(records),
            head=head if isinstance(head, str) else ZERO_HASH,
            signed=signed,
            key_checked=self.key is not None and signed,
            errors=tuple(errors),
        )
        return LedgerState(tuple(records), verification)

    def _tail(self) -> Tuple[int, str]:
        """The next sequence number and previous hash, rejecting a corrupt last line."""
        if not self.path.exists():
            return 0, ZERO_HASH
        try:
            last = last_nonempty_line(self.path)
        except (OSError, UnicodeError) as exc:
            raise LedgerError(
                f"The ledger tail could not be read: {exc}.",
                "appending to an unreadable chain would break its continuity.",
                "check the path and permissions, then retry.",
            ) from exc
        if not last:
            return 0, ZERO_HASH
        try:
            value = json.loads(last)
        except json.JSONDecodeError as exc:
            raise LedgerError(
                f"The last ledger line is not valid JSON: {exc.msg}.",
                "a new record cannot extend a chain whose tail is corrupt.",
                "restore the ledger from a verified copy before recording more events.",
            ) from exc
        seq = value.get("seq") if isinstance(value, dict) else None
        digest = value.get("hash") if isinstance(value, dict) else None
        if isinstance(seq, bool) or not isinstance(seq, int) or not isinstance(digest, str):
            raise LedgerError(
                "The last ledger record has no valid seq/hash pair.",
                "a new record cannot extend a chain whose tail is corrupt.",
                "restore the ledger from a verified copy before recording more events.",
            )
        return seq + 1, digest
