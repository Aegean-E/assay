"""A deterministic treasury-agent scenario that shows the product in one command."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Tuple

from .ledger import Ledger, LedgerState
from .model import Event
from .policy import Finding, Policy, drift_findings, parse_policy, review_events
from .report import build_pack, write_report
from .storage import write_text_atomic

DEMO_POLICY = {
    "schema": 1,
    "name": "treasury-guardrail",
    "default": "allow",
    "rules": [
        {"id": "block-shell", "action": "shell.*", "effect": "deny"},
        {"id": "transfer-cap", "action": "payments.*", "effect": "deny", "amount_over": 10000},
        {"id": "approve-transfers", "action": "payments.transfer", "effect": "require_approval"},
    ],
}


@dataclass(frozen=True)
class DemoResult:
    """Everything the demo wrote, so tests and the CLI share one contract."""

    directory: Path
    ledger_path: Path
    policy_path: Path
    markdown_path: Path
    json_path: Path
    state: LedgerState
    policy: Policy
    findings: Tuple[Finding, ...]


def _events() -> Tuple[Event, ...]:
    return (
        Event.create("agent:treasury-bot", "invoices.read", target="invoices:2026-10",
                     ts="2026-10-23T09:00:00Z", metadata={"invoice_count": 14}),
        Event.create("agent:treasury-bot", "payments.transfer", target="acct:vendor-17",
                     ts="2026-10-23T09:01:00Z",
                     metadata={"amount": 4200, "approved_by": "controller@acme.example"}),
        Event.create("agent:treasury-bot", "payments.transfer", target="acct:vendor-22",
                     ts="2026-10-23T09:02:00Z", metadata={"amount": 25000}),
        Event.create("agent:ops-bot", "shell.exec", target="prod-db-1",
                     ts="2026-10-23T09:03:00Z", metadata={"command": "pg_dump"}),
        Event.create("agent:support-bot", "crm.export", target="segment:churn-risk",
                     ts="2026-10-23T09:04:00Z", metadata={"rows": 312}),
    )


def run_demo(directory: Path) -> DemoResult:
    """Create a policy, a signed-off chain, findings and both evidence packs."""
    directory.mkdir(parents=True, exist_ok=True)
    policy = parse_policy(DEMO_POLICY)
    policy_path = directory / "policy.json"
    write_text_atomic(policy_path, json.dumps(DEMO_POLICY, indent=2) + "\n")
    ledger_path = directory / "ledger.jsonl"
    ledger = Ledger(ledger_path)
    reference = policy.reference()
    for event in _events():
        ledger.append(replace(event, policy=reference))
    state = ledger.inspect()
    findings = tuple(review_events(policy, state.records) + drift_findings(policy, state.records))
    pack = build_pack(str(ledger_path), state, policy)
    markdown_path = directory / "evidence.md"
    json_path = directory / "evidence.json"
    write_report(pack, markdown_path, "md")
    write_report(pack, json_path, "json")
    return DemoResult(directory, ledger_path, policy_path, markdown_path, json_path,
                      state, policy, findings)
