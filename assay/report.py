"""Self-contained evidence packs in Markdown and JSON."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from .ledger import LedgerState
from .model import utc_now
from .policy import Finding, Policy, drift_findings, review_events
from .storage import write_text_atomic
from .version import VERSION

EVENTS_IN_MARKDOWN = 200


def _event(envelope: Mapping[str, Any]) -> Mapping[str, Any]:
    value = envelope.get("event")
    return value if isinstance(value, Mapping) else {}


def _finding_summary(findings: Sequence[Finding]) -> Dict[str, int]:
    counts = Counter(finding.effect for finding in findings)
    return {
        "total": len(findings),
        "denied": counts.get("deny", 0),
        "require_approval": counts.get("require_approval", 0),
        "policy_drift": counts.get("policy_drift", 0),
    }


def build_pack(ledger_name: str, state: LedgerState,
               policy: Optional[Policy]) -> Dict[str, Any]:
    """Assemble the JSON evidence pack from verified records and an optional policy."""
    findings: List[Finding] = []
    if policy is not None:
        findings.extend(review_events(policy, state.records))
        findings.extend(drift_findings(policy, state.records))
    findings.sort(key=lambda item: (item.seq, item.rule_id))
    outcomes = Counter(str(_event(record).get("outcome", "")) for record in state.records)
    actors = sorted({str(_event(record).get("actor", "")) for record in state.records})
    actions = sorted({str(_event(record).get("action", "")) for record in state.records})
    coverage = {"recorded": 0, "matching": 0}
    for record in state.records:
        reference = _event(record).get("policy")
        if isinstance(reference, Mapping) and isinstance(reference.get("digest"), str):
            coverage["recorded"] += 1
            if policy is not None and reference["digest"] == policy.digest:
                coverage["matching"] += 1
    if not state.verification.ok:
        verdict = "FAIL"
    elif findings:
        verdict = "REVIEW"
    else:
        verdict = "PASS"
    return {
        "schema": 1,
        "generated_at": utc_now(),
        "tool": {"name": "assay", "version": VERSION},
        "verdict": verdict,
        "ledger": {
            "name": ledger_name,
            "records": state.verification.records,
            "head": state.verification.head,
            "verified": state.verification.ok,
            "signed": state.verification.signed,
            "key_checked": state.verification.key_checked,
            "errors": list(state.verification.errors),
        },
        "policy": None if policy is None else {
            "name": policy.name,
            "digest": policy.digest,
            "default": policy.default,
            "rules": len(policy.rules),
            "document": policy.to_dict(),
        },
        "summary": {
            "events": len(state.records),
            "findings": _finding_summary(findings),
            "outcomes": dict(sorted(outcomes.items())),
            "actors": actors,
            "actions": actions,
            "policy_coverage": coverage,
        },
        "findings": [finding.to_dict() for finding in findings],
        "events": [dict(record) for record in state.records],
        "disclaimer": "Evidence support, not a legal certification or legal advice.",
    }


def _cell(value: Any, limit: int = 80) -> str:
    text = str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _bullets(values: Sequence[str]) -> str:
    return ", ".join(_cell(value, 60) for value in values) or "none"


def render_markdown(pack: Mapping[str, Any]) -> str:
    """Render the pack as a reviewable Markdown document."""
    ledger = pack["ledger"]
    policy = pack["policy"]
    summary = pack["summary"]
    findings = pack["findings"]
    lines = [
        "# Assay Evidence Pack",
        "",
        f"**Verdict: {pack['verdict']}**",
        "",
        f"Generated {pack['generated_at']} by Assay {pack['tool']['version']}.",
        "",
        "## Ledger",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Name | {_cell(ledger['name'], 120)} |",
        f"| Records | {ledger['records']} |",
        f"| Chain verified | {'yes' if ledger['verified'] else 'no'} |",
        f"| Signed | {'yes' if ledger['signed'] else 'no'} |",
        f"| Signature checked | {'yes' if ledger['key_checked'] else 'no'} |",
        f"| Head | `{ledger['head']}` |",
        "",
    ]
    if ledger["errors"]:
        lines += ["### Chain errors", ""]
        lines += [f"- {_cell(error, 200)}" for error in ledger["errors"]]
        lines += [""]
    lines += [
        "## Policy",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Name | {_cell(policy['name'] if policy else 'not supplied', 80)} |",
        f"| Digest | {('`' + policy['digest'] + '`') if policy else 'not supplied'} |",
        f"| Default effect | {_cell(policy['default'] if policy else 'n/a', 40)} |",
        f"| Rules | {policy['rules'] if policy else 0} |",
        f"| Events citing a policy | {summary['policy_coverage']['recorded']} of {summary['events']} |",
        f"| Events matching this policy | {summary['policy_coverage']['matching']} |",
        "",
    ]
    if policy:
        lines += [
            "### Policy rules",
            "",
            "| Id | Action | Effect | Conditions |",
            "|---|---|---|---|",
        ]
        for rule in policy.get("document", {}).get("rules", []):
            conditions = []
            if "amount_over" in rule:
                conditions.append(f"amount > {rule['amount_over']:g}")
            if "amount_under" in rule:
                conditions.append(f"amount < {rule['amount_under']:g}")
            if "metadata" in rule:
                conditions.append(json.dumps(rule["metadata"], sort_keys=True,
                                             separators=(",", ":")))
            lines.append(
                f"| {_cell(rule.get('id'), 30)} | {_cell(rule.get('action'), 40)} "
                f"| {_cell(rule.get('effect'), 20)} | {_cell(', '.join(conditions) or 'none', 100)} |"
            )
        lines += [""]
    lines += [
        "## Summary",
        "",
        f"- Events: **{summary['events']}**",
        f"- Findings: **{summary['findings']['total']}** "
        f"(denied {summary['findings']['denied']}, "
        f"approval {summary['findings']['require_approval']}, "
        f"policy drift {summary['findings']['policy_drift']})",
        f"- Actors: {_bullets(summary['actors'])}",
        f"- Actions: {_bullets(summary['actions'])}",
        "",
    ]
    if findings:
        lines += [
            "## Findings",
            "",
            "| Seq | Actor | Action | Effect | Rule | Reason |",
            "|---:|---|---|---|---|---|",
        ]
        for finding in findings:
            lines.append(
                f"| {finding['seq']} | {_cell(finding['actor'], 40)} "
                f"| {_cell(finding['action'], 40)} | {_cell(finding['effect'], 20)} "
                f"| {_cell(finding['rule_id'], 30)} | {_cell(finding['reason'], 120)} |"
            )
        lines += [""]
    else:
        lines += ["## Findings", "", "No policy findings.", ""]
    events = pack["events"]
    lines += [
        "## Events",
        "",
        "| Seq | Time | Actor | Action | Outcome | Target |",
        "|---:|---|---|---|---|---|",
    ]
    for envelope in events[:EVENTS_IN_MARKDOWN]:
        event = _event(envelope)
        lines.append(
            f"| {envelope.get('seq')} | {_cell(event.get('ts'), 30)} "
            f"| {_cell(event.get('actor'), 40)} | {_cell(event.get('action'), 40)} "
            f"| {_cell(event.get('outcome'), 16)} | {_cell(event.get('target'), 40)} |"
        )
    if len(events) > EVENTS_IN_MARKDOWN:
        lines += [
            "",
            f"Showing the first {EVENTS_IN_MARKDOWN} of {len(events)} events; "
            "the JSON pack contains every record.",
        ]
    lines += [
        "",
        "## Verification",
        "",
        "The chain is valid when every `seq` is contiguous, every `prev` equals the previous "
        "record hash, and every record hash matches its canonical payload. Re-run:",
        "",
        "```bash",
        f'assay verify --ledger "{ledger["name"]}"',
        "```",
        "",
        f"_{pack['disclaimer']}_",
        "",
    ]
    return "\n".join(lines)


def write_report(pack: Mapping[str, Any], path: Path, fmt: str = "md") -> None:
    """Write Markdown or JSON through the atomic storage helper."""
    if fmt == "json":
        content = json.dumps(pack, indent=2, sort_keys=True, ensure_ascii=False,
                             allow_nan=False) + "\n"
    elif fmt == "md":
        content = render_markdown(pack)
    else:
        raise ValueError(f"unknown report format {fmt}")
    write_text_atomic(path, content)
