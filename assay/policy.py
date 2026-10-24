"""Declarative agent policy evaluation and retrospective findings."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from .errors import ValidationError
from .model import Event, canonical_bytes

EFFECTS = ("allow", "deny", "require_approval")
_RULE_FIELDS = frozenset({"id", "action", "effect", "amount_over", "amount_under", "metadata"})
_POLICY_FIELDS = frozenset({"schema", "name", "default", "rules"})


@dataclass(frozen=True)
class Rule:
    """One first-match policy rule; `*` is the only glob supported in `action`."""

    id: str
    action: str
    effect: str
    amount_over: Optional[float] = None
    amount_under: Optional[float] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def match(self, event: Event) -> Tuple[bool, str, bool]:
        """Whether the rule applies, a reviewable reason, and whether the amount is unverifiable."""
        if not fnmatch.fnmatchcase(event.action, self.action):
            return False, "", False
        for key, expected in self.metadata.items():
            if event.metadata.get(key) != expected:
                return False, "", False
        if self.amount_over is None and self.amount_under is None:
            return True, f"matched rule '{self.id}'", False
        amount = event.metadata.get("amount")
        if isinstance(amount, bool) or not isinstance(amount, (int, float)) \
                or not math.isfinite(float(amount)):
            return True, "amount is missing or not numeric, so the threshold cannot be verified", True
        above = self.amount_over is not None and amount > self.amount_over
        below = self.amount_under is not None and amount < self.amount_under
        if self.amount_over is not None and self.amount_under is not None:
            if not (above or below):
                return False, "", False
            return True, f"amount {amount:g} is outside the allowed band", False
        if self.amount_over is not None:
            if not above:
                return False, "", False
            return True, f"amount {amount:g} exceeds {self.amount_over:g}", False
        if not below:
            return False, "", False
        return True, f"amount {amount:g} is below {self.amount_under:g}", False

    def to_dict(self) -> Dict[str, Any]:
        value: Dict[str, Any] = {"id": self.id, "action": self.action, "effect": self.effect}
        if self.amount_over is not None:
            value["amount_over"] = self.amount_over
        if self.amount_under is not None:
            value["amount_under"] = self.amount_under
        if self.metadata:
            value["metadata"] = dict(self.metadata)
        return value


@dataclass(frozen=True)
class Decision:
    """The effective rule and reason for one event."""

    effect: str
    rule_id: Optional[str]
    reason: str


@dataclass(frozen=True)
class Finding:
    """A policy violation or an unverifiable requirement, tied to its ledger position."""

    seq: int
    event_id: str
    actor: str
    action: str
    effect: str
    rule_id: str
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "event_id": self.event_id,
            "actor": self.actor,
            "action": self.action,
            "effect": self.effect,
            "rule_id": self.rule_id,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class Policy:
    """A validated policy document with a stable digest."""

    name: str
    default: str
    rules: Tuple[Rule, ...]
    digest: str

    def evaluate(self, event: Event) -> Decision:
        """First matching rule wins; the default applies when none matches."""
        for rule in self.rules:
            matched, reason, unverifiable = rule.match(event)
            if not matched:
                continue
            if unverifiable:
                return Decision("deny", rule.id, reason)
            return Decision(rule.effect, rule.id, reason)
        return Decision(self.default, None, "no rule matched; default applied")

    def review(self, event: Event, seq: int = -1) -> Optional[Finding]:
        """Return a finding when the action is denied or lacks a required approval."""
        decision = self.evaluate(event)
        if decision.effect == "deny":
            return Finding(seq, event.id, event.actor, event.action, "deny",
                           decision.rule_id or "default", decision.reason)
        if decision.effect == "require_approval" and not _approved(event):
            return Finding(seq, event.id, event.actor, event.action, "require_approval",
                           decision.rule_id or "default",
                           "approval required but metadata.approved_by is missing")
        return None

    def reference(self) -> Dict[str, str]:
        """The compact policy reference stored with each event."""
        return {"name": self.name, "digest": self.digest}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": 1,
            "name": self.name,
            "default": self.default,
            "rules": [rule.to_dict() for rule in self.rules],
        }


def _approved(event: Event) -> bool:
    value = event.metadata.get("approved_by")
    return isinstance(value, str) and bool(value.strip())


def _finite(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) \
            or not math.isfinite(float(value)):
        raise ValidationError(
            f"Policy field '{name}' must be a finite number.",
            "amount limits are compared numerically with event metadata.",
            f"set '{name}' to a finite non-negative number.",
        )
    number = float(value)
    if number < 0:
        raise ValidationError(
            f"Policy field '{name}' is negative.",
            "a negative limit has no business meaning and hides a typo.",
            f"set '{name}' to zero or a positive number.",
        )
    return number


def _parse_rule(value: Any, position: int) -> Rule:
    if not isinstance(value, dict):
        raise ValidationError(
            f"Policy rule {position} is not an object.",
            "a rule must declare id, action and effect.",
            "write each rule as a JSON object.",
        )
    unknown = set(value) - _RULE_FIELDS
    if unknown:
        raise ValidationError(
            f"Policy rule {position} has unknown field(s): {', '.join(sorted(unknown))}.",
            "a misspelled rule field would silently change the guardrail.",
            "remove the field or use one of: id, action, effect, amount_over, amount_under, metadata.",
        )
    rule_id = value.get("id")
    action = value.get("action")
    effect = value.get("effect")
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise ValidationError(
            f"Policy rule {position} has no id.",
            "findings cite the rule id that produced them.",
            "give every rule a short unique id.",
        )
    if not isinstance(action, str) or not action.strip():
        raise ValidationError(
            f"Policy rule '{rule_id}' has no action pattern.",
            "a rule with an empty pattern cannot match anything.",
            "set action to a tool name or a glob such as 'payments.*'.",
        )
    if effect not in EFFECTS:
        raise ValidationError(
            f"Policy rule '{rule_id}' has unknown effect '{effect}'.",
            f"the contract allows: {', '.join(EFFECTS)}.",
            "pick one of the listed effects.",
        )
    amount_over = _finite(value["amount_over"], f"{rule_id}.amount_over") \
        if "amount_over" in value else None
    amount_under = _finite(value["amount_under"], f"{rule_id}.amount_under") \
        if "amount_under" in value else None
    if amount_over is not None and amount_under is not None and amount_under >= amount_over:
        raise ValidationError(
            f"Policy rule '{rule_id}' has amount_under not below amount_over.",
            "the band would be empty or inverted, so no amount could fall outside it.",
            "set amount_under below amount_over, or remove one of them.",
        )
    metadata = value.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ValidationError(
            f"Policy rule '{rule_id}' metadata is not an object.",
            "metadata conditions are exact key/value matches.",
            "write metadata as an object of expected values.",
        )
    canonical_bytes(metadata)
    return Rule(rule_id.strip(), action.strip(), effect, amount_over, amount_under, dict(metadata))


def parse_policy(value: Any) -> Policy:
    """Validate a decoded policy document and compute its digest."""
    if not isinstance(value, dict):
        raise ValidationError(
            "A policy must be a JSON object.",
            "the loader needs named fields and a rules array.",
            "start from examples/policy.json.",
        )
    unknown = set(value) - _POLICY_FIELDS
    if unknown:
        raise ValidationError(
            f"The policy has unknown field(s): {', '.join(sorted(unknown))}.",
            "a misspelled top-level field would silently weaken the guardrail.",
            "remove the field or use one of: schema, name, default, rules.",
        )
    if value.get("schema") != 1:
        raise ValidationError(
            "The policy schema must be 1.",
            "an unversioned policy cannot be interpreted safely.",
            "set \"schema\": 1.",
        )
    name = value.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValidationError(
            "The policy has no name.",
            "evidence packs cite the policy that produced each finding.",
            "set a short policy name.",
        )
    default = value.get("default", "deny")
    if default not in EFFECTS:
        raise ValidationError(
            f"Unknown default effect '{default}'.",
            f"the contract allows: {', '.join(EFFECTS)}.",
            "pick one of the listed effects.",
        )
    raw_rules = value.get("rules", [])
    if not isinstance(raw_rules, list):
        raise ValidationError(
            "Policy rules must be an array.",
            "rule order decides which effect wins.",
            "write rules as a JSON array.",
        )
    if len(raw_rules) > 1000:
        raise ValidationError(
            "The policy has more than 1000 rules.",
            "an oversized policy is hard to review and slow to evaluate.",
            "split it into focused policies or reduce the rule count.",
        )
    rules = tuple(_parse_rule(rule, index + 1) for index, rule in enumerate(raw_rules))
    identifiers = [rule.id for rule in rules]
    if len(set(identifiers)) != len(identifiers):
        raise ValidationError(
            "Policy rule ids are not unique.",
            "findings cite a rule id, so an id must select exactly one rule.",
            "rename the duplicate rule ids.",
        )
    normalized = {
        "schema": 1,
        "name": name.strip(),
        "default": default,
        "rules": [rule.to_dict() for rule in rules],
    }
    digest = hashlib.sha256(canonical_bytes(normalized)).hexdigest()
    return Policy(name.strip(), default, rules, digest)


PACKS_DIR = Path(__file__).parent / "packs"


def list_packs() -> List[str]:
    """List available built-in policy pack names."""
    if not PACKS_DIR.is_dir():
        return []
    return sorted(p.stem for p in PACKS_DIR.glob("*.json"))


def load_pack(name: str) -> Policy:
    """Load a built-in policy pack by name with an actionable failure triad."""
    pack_name = name.strip()
    if pack_name.startswith("pack:"):
        pack_name = pack_name[5:]
    if pack_name.endswith(".json"):
        pack_name = pack_name[:-5]
    path = PACKS_DIR / f"{pack_name}.json"
    if not path.is_file():
        available = list_packs()
        raise ValidationError(
            f"Unknown policy pack '{name}'.",
            f"available policy packs are: {', '.join(available)}.",
            f"select one of the available packs ({', '.join(available)}) or provide a path to a JSON file.",
        )
    return load_policy(path)


def load_policy(target: Union[Path, str]) -> Policy:
    """Read and validate a policy file or built-in pack with an actionable failure triad."""
    if isinstance(target, str):
        cleaned = target.strip()
        if cleaned.startswith("pack:"):
            return load_pack(cleaned[5:])
        path = Path(cleaned)
        if not path.is_file() and (PACKS_DIR / f"{cleaned}.json").is_file():
            return load_pack(cleaned)
    else:
        path = Path(target)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValidationError(
            f"The policy '{path}' could not be read: {exc}.",
            "review and report generation need the policy that was in force.",
            "check the path and permissions, then retry.",
        ) from exc
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValidationError(
            f"The policy is not valid JSON: {exc.msg} (line {exc.lineno}).",
            "a malformed policy cannot be evaluated deterministically.",
            "fix the JSON syntax and retry.",
        ) from exc
    return parse_policy(value)


def review_events(policy: Policy, records: Sequence[Mapping[str, Any]]) -> List[Finding]:
    """Evaluate every stored event, attaching its ledger sequence to each finding."""
    findings: List[Finding] = []
    for index, envelope in enumerate(records):
        raw = envelope.get("event")
        event = Event.from_dict(raw if isinstance(raw, Mapping) else {})
        finding = policy.review(event, index)
        if finding is not None:
            findings.append(Finding(index, finding.event_id, finding.actor, finding.action,
                                    finding.effect, finding.rule_id, finding.reason))
    return findings


def drift_findings(policy: Policy, records: Sequence[Mapping[str, Any]]) -> List[Finding]:
    """Flag events recorded under a different policy digest than the one under review."""
    findings: List[Finding] = []
    for index, envelope in enumerate(records):
        raw = envelope.get("event")
        if not isinstance(raw, Mapping):
            continue
        reference = raw.get("policy")
        if not isinstance(reference, Mapping):
            continue
        digest = reference.get("digest")
        if isinstance(digest, str) and digest != policy.digest:
            event = Event.from_dict(raw)
            findings.append(Finding(
                index, event.id, event.actor, event.action, "policy_drift", "policy-digest",
                f"event was recorded under policy digest {digest[:12]}..., "
                f"but the reviewed policy is {policy.digest[:12]}...",
            ))
    return findings
