"""Append-only anchor journal that commits to a ledger head."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .errors import AnchorError, ValidationError
from .model import ZERO_HASH, canonical_bytes, normalize_timestamp, utc_now
from .storage import append_line, last_nonempty_line, read_lines

ANCHOR_SCHEMA = 1
ANCHOR_FIELDS = frozenset(
    {"schema", "ledger", "seq", "head", "created_at", "key_id", "prev", "hash"}
)
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_LEDGER = re.compile(r"^[^\x00-\x1f\x7f]{1,128}$")


def anchor_payload(*, schema: int, ledger: str, seq: int, head: str,
                   created_at: str, key_id: Optional[str], prev: str) -> bytes:
    """The exact bytes an anchor hash covers; documented in docs/SECURITY.md."""
    return canonical_bytes({
        "schema": schema,
        "ledger": ledger,
        "seq": seq,
        "head": head,
        "created_at": created_at,
        "key_id": key_id,
        "prev": prev,
    })


def anchor_hash(*, schema: int, ledger: str, seq: int, head: str,
                created_at: str, key_id: Optional[str], prev: str) -> str:
    """SHA-256 over the canonical anchor payload."""
    return hashlib.sha256(
        anchor_payload(schema=schema, ledger=ledger, seq=seq, head=head,
                       created_at=created_at, key_id=key_id, prev=prev)
    ).hexdigest()


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValidationError(
            f"The anchor {name} must be a lowercase SHA-256 digest.",
            "a non-canonical digest cannot be compared across implementations.",
            f"pass 64 lowercase hex characters for {name}.",
        )
    return value


def _sequence(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValidationError(
            "The anchor seq must be a non-negative integer.",
            "an anchor commits to one ledger record index.",
            "pass the zero-based seq of the last covered record.",
        )
    return value


def _ledger_label(value: Any) -> str:
    if not isinstance(value, str) or not _LEDGER.fullmatch(value):
        raise ValidationError(
            "The anchor ledger label must be 1-128 printable characters.",
            "the label names the ledger an anchor covers.",
            "pass a short file or deployment name without control characters.",
        )
    return value


def _key_identifier(value: Any) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str) or not _KEY_ID.fullmatch(value):
        raise ValidationError(
            "The anchor key id must be an identifier or null.",
            "the key id names the signing key without carrying secret material.",
            "use 1-64 characters from letters, digits, dot, colon, dash or underscore.",
        )
    return value


def _created_at(value: Any) -> str:
    if value is None:
        return utc_now()
    return normalize_timestamp(value)


def _json_line(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class Anchor:
    """One immutable commitment to a ledger seq and hash."""

    schema: int
    ledger: str
    seq: int
    head: str
    created_at: str
    key_id: Optional[str]
    prev: str
    hash: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "ledger": self.ledger,
            "seq": self.seq,
            "head": self.head,
            "created_at": self.created_at,
            "key_id": self.key_id,
            "prev": self.prev,
            "hash": self.hash,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Anchor":
        if not isinstance(value, Mapping):
            raise ValidationError(
                "An anchor record must be a JSON object.",
                "the journal stores one canonical object per line.",
                "restore the journal from a verified copy.",
            )
        keys = set(value)
        unknown = keys - ANCHOR_FIELDS
        if unknown:
            raise ValidationError(
                f"The anchor has unknown field(s): {', '.join(sorted(unknown))}.",
                "unknown fields are not covered by the hash and could hide data.",
                "remove the extra fields and restore the journal from a verified copy.",
            )
        missing = ANCHOR_FIELDS - keys
        if missing:
            raise ValidationError(
                f"The anchor is missing field(s): {', '.join(sorted(missing))}.",
                "a partial anchor cannot be verified.",
                "restore the journal from a verified copy.",
            )
        schema = value["schema"]
        if isinstance(schema, bool) or schema != ANCHOR_SCHEMA:
            raise ValidationError(
                f"The anchor schema {schema!r} is not supported.",
                "a newer format needs an explicit migration before it can be read.",
                f"use schema {ANCHOR_SCHEMA} or upgrade Assay.",
            )
        ledger = _ledger_label(value["ledger"])
        seq = _sequence(value["seq"])
        head = _digest(value["head"], "head")
        prev = _digest(value["prev"], "prev")
        created_at = value["created_at"]
        if not isinstance(created_at, str) or normalize_timestamp(created_at) != created_at:
            raise ValidationError(
                "The anchor created_at is not a normalized UTC timestamp.",
                "the hash covers the exact stored text, so the form must be canonical.",
                "write timestamps as e.g. 2026-10-24T09:00:00Z.",
            )
        key_id = _key_identifier(value["key_id"])
        expected = anchor_hash(schema=schema, ledger=ledger, seq=seq, head=head,
                               created_at=created_at, key_id=key_id, prev=prev)
        stored = _digest(value["hash"], "hash")
        if stored != expected:
            raise ValidationError(
                "The anchor hash does not match its payload.",
                "the record changed after it was committed.",
                "restore the journal from a verified copy.",
            )
        return cls(schema=schema, ledger=ledger, seq=seq, head=head,
                   created_at=created_at, key_id=key_id, prev=prev, hash=stored)


@dataclass(frozen=True)
class AnchorVerification:
    """The outcome of walking the whole anchor journal once."""

    ok: bool
    anchors: int
    head: str
    errors: Tuple[str, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "anchors": self.anchors,
            "head": self.head,
            "errors": list(self.errors),
        }


@dataclass(frozen=True)
class AnchorState:
    """Anchor records and their verification, read in one pass."""

    records: Tuple[Dict[str, Any], ...]
    verification: AnchorVerification

    @property
    def latest(self) -> Optional[Dict[str, Any]]:
        return self.records[-1] if self.records else None


class AnchorJournal:
    """Persist anchors in a JSONL file whose every record commits to its predecessor."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def append(self, *, ledger: str, seq: int, head: str,
               key_id: Optional[str] = None,
               created_at: Optional[str] = None) -> Dict[str, Any]:
        """Append one anchor and return the stored record."""
        prev, last_seq = self._tail()
        value: Dict[str, Any] = {
            "schema": ANCHOR_SCHEMA,
            "ledger": _ledger_label(ledger),
            "seq": _sequence(seq),
            "head": _digest(head, "head"),
            "created_at": _created_at(created_at),
            "key_id": _key_identifier(key_id),
            "prev": prev,
        }
        if value["seq"] < last_seq:
            raise ValidationError(
                f"Anchor seq {value['seq']} moves backwards from {last_seq}.",
                "a journal must not roll back the latest committed head.",
                "append the current head or start a new journal for another ledger.",
            )
        value["hash"] = anchor_hash(**value)
        try:
            append_line(self.path, _json_line(value))
        except OSError as exc:
            raise AnchorError(
                f"The anchor journal could not be appended: {exc}.",
                "the anchored head must be durable before it counts as published.",
                "check the path, free space and permissions, then retry.",
            ) from exc
        return value

    def inspect(self) -> AnchorState:
        """Read and verify every anchor; malformed or tampered records become findings."""
        if not self.path.is_file():
            raise AnchorError(
                f"The anchor journal '{self.path}' does not exist.",
                "verification needs the anchor file it should compare.",
                "run `assay anchor` first, or pass --anchors with the correct path.",
            )
        try:
            lines = list(read_lines(self.path))
        except (OSError, UnicodeError) as exc:
            raise AnchorError(
                f"The anchor journal could not be read: {exc}.",
                "an unreadable journal cannot prove anything about the ledger.",
                "check the path and permissions, then retry.",
            ) from exc
        records: List[Dict[str, Any]] = []
        errors: List[str] = []
        expected_prev = ZERO_HASH
        last_seq = -1
        for number, line in enumerate(lines, start=1):
            if not line.strip():
                errors.append(f"line {number}: blank line")
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(f"line {number}: invalid JSON ({exc.msg})")
                continue
            if not isinstance(value, dict):
                errors.append(f"line {number}: anchor is not an object")
                continue
            try:
                anchor = Anchor.from_dict(value)
            except ValidationError as exc:
                errors.append(f"line {number}: {exc.message}")
                continue
            if anchor.prev != expected_prev:
                errors.append(f"line {number}: prev does not match the previous anchor")
            if anchor.seq < last_seq:
                errors.append(f"line {number}: seq {anchor.seq} moves backwards from {last_seq}")
            records.append(anchor.to_dict())
            expected_prev = anchor.hash
            last_seq = max(last_seq, anchor.seq)
        head = records[-1]["hash"] if records else ZERO_HASH
        verification = AnchorVerification(
            ok=not errors,
            anchors=len(records),
            head=head,
            errors=tuple(errors),
        )
        return AnchorState(tuple(records), verification)

    def _tail(self) -> Tuple[str, int]:
        """The previous anchor hash and seq, rejecting a corrupt last line."""
        if not self.path.exists():
            return ZERO_HASH, -1
        try:
            last = last_nonempty_line(self.path)
        except (OSError, UnicodeError) as exc:
            raise AnchorError(
                f"The anchor journal tail could not be read: {exc}.",
                "appending to an unreadable journal would break its continuity.",
                "check the path and permissions, then retry.",
            ) from exc
        if not last:
            return ZERO_HASH, -1
        try:
            value = json.loads(last)
        except json.JSONDecodeError as exc:
            raise AnchorError(
                f"The last anchor line is not valid JSON: {exc.msg}.",
                "a new anchor cannot extend a journal whose tail is corrupt.",
                "restore the journal from a verified copy before anchoring again.",
            ) from exc
        try:
            anchor = Anchor.from_dict(value) if isinstance(value, dict) else None
        except ValidationError as exc:
            raise AnchorError(
                f"The last anchor line is invalid: {exc.message}",
                "a new anchor cannot extend a journal whose tail is corrupt.",
                "restore the journal from a verified copy before anchoring again.",
            ) from exc
        if anchor is None:
            raise AnchorError(
                "The last anchor line is not an object.",
                "a new anchor cannot extend a journal whose tail is corrupt.",
                "restore the journal from a verified copy before anchoring again.",
            )
        return anchor.hash, anchor.seq
