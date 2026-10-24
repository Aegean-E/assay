"""Command-line interface for recording, verifying and reviewing agent evidence."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from . import anchor as anchor_module
from .adapters import parse_event_stream
from .anchor import AnchorJournal
from .demo import run_demo
from .errors import AnchorError, AssayError, LedgerError, ValidationError
from .ledger import Ledger, LedgerState
from .model import OUTCOMES, Event, normalize_timestamp
from .policy import (
    Finding,
    Policy,
    drift_findings,
    list_packs,
    load_pack,
    load_policy,
    review_events,
)
from .report import build_pack, render_markdown, write_report
from .version import VERSION

DEFAULT_LEDGER = Path(".assay") / "ledger.jsonl"
DEFAULT_ANCHORS = Path(".assay") / "anchors.jsonl"


class Parser(argparse.ArgumentParser):
    """Turn argument errors into the Assay triad instead of an unlabelled usage dump."""

    def error(self, message: str) -> None:
        raise ValidationError(
            f"Invalid command line: {message}.",
            "the arguments do not match the command contract.",
            "run `assay --help` or `assay <command> --help`.",
        )


def _add_ledger(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER,
                        help=f"ledger path (default: {DEFAULT_LEDGER})")
    parser.add_argument("--hmac-key-env", metavar="NAME",
                        help="environment variable holding the HMAC key (never pass the key itself)")


def _add_policy(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--policy", help="policy JSON file or built-in pack (e.g. pack:payments)")


def build_parser() -> Parser:
    """The complete command surface; every subcommand returns an exit code."""
    parser = Parser(
        prog="assay",
        description="Tamper-evident audit evidence for AI agents.",
    )
    parser.add_argument("--version", action="version", version=f"assay {VERSION}")
    commands = parser.add_subparsers(dest="command", required=True)

    record = commands.add_parser("record", help="append one agent event")
    record.add_argument("--actor", required=True, help="agent or principal that acted")
    record.add_argument("--action", required=True, help="tool or operation name")
    record.add_argument("--outcome", choices=OUTCOMES, default="success")
    record.add_argument("--target", default="", help="resource the action addressed")
    record.add_argument("--metadata", help="JSON object, or @path to a JSON file")
    record.add_argument("--ts", help="ISO-8601 time or Unix seconds (default: now)")
    _add_policy(record)
    _add_ledger(record)
    record.add_argument("--json", action="store_true", help="print the stored envelope")
    record.set_defaults(handler=_cmd_record)

    ingest = commands.add_parser("ingest", help="append events from a JSONL stream")
    ingest.add_argument("--file", default="-", help="JSONL file, or - for stdin")
    ingest.add_argument("--format", dest="input_format",
                        choices=("generic", "mcp", "openai", "langgraph", "crewai"),
                        default="generic", help="adapter for the incoming records")
    ingest.add_argument("--actor", help="fallback actor when a record omits one")
    _add_policy(ingest)
    _add_ledger(ingest)
    ingest.add_argument("--json", action="store_true", help="print a machine-readable summary")
    ingest.set_defaults(handler=_cmd_ingest)

    verify = commands.add_parser("verify", help="verify the hash chain and signatures")
    _add_ledger(verify)
    verify.add_argument("--anchors", type=Path,
                        help="anchor journal to compare with the ledger")
    verify.add_argument("--json", action="store_true", help="print the verification as JSON")
    verify.set_defaults(handler=_cmd_verify)

    anchor = commands.add_parser("anchor", help="commit the verified ledger head to a journal")
    _add_ledger(anchor)
    anchor.add_argument("--anchors", type=Path, default=DEFAULT_ANCHORS,
                        help=f"anchor journal path (default: {DEFAULT_ANCHORS})")
    anchor.add_argument("--ledger-label",
                        help="label stored in the anchor (default: ledger file name)")
    anchor.add_argument("--key-id", metavar="ID",
                        help="name of the HMAC key that signed the anchored records")
    anchor.add_argument("--json", action="store_true", help="print the stored anchor record")
    anchor.set_defaults(handler=_cmd_anchor)

    review = commands.add_parser("review", help="evaluate the ledger against a policy")
    _add_policy(review)
    _add_ledger(review)
    review.add_argument("--json", action="store_true", help="print findings as JSON")
    review.set_defaults(handler=_cmd_review)

    report = commands.add_parser("report", help="write a self-contained evidence pack")
    _add_policy(report)
    _add_ledger(report)
    report.add_argument("--out", type=Path, help="output path (default: stdout)")
    report.add_argument("--format", dest="report_format", choices=("md", "json"), default="md")
    report.set_defaults(handler=_cmd_report)

    demo = commands.add_parser("demo", help="run the treasury-agent scenario end to end")
    demo.add_argument("--out", type=Path, help="directory for demo artefacts (default: temp)")
    demo.add_argument("--json", action="store_true", help="print a machine-readable summary")
    demo.set_defaults(handler=_cmd_demo)

    policy_parser = commands.add_parser("policy", help="inspect built-in guardrail policy packs")
    policy_sub = policy_parser.add_subparsers(dest="policy_command", required=True)

    policy_list = policy_sub.add_parser("list", help="list available policy packs")
    policy_list.add_argument("--json", action="store_true", help="output packs as JSON")
    policy_list.set_defaults(handler=_cmd_policy_list)

    policy_show = policy_sub.add_parser("show", help="display details of a policy pack or file")
    policy_show.add_argument("name", help="policy pack name (e.g. payments) or path to JSON file")
    policy_show.add_argument("--json", action="store_true", help="output canonical JSON")
    policy_show.set_defaults(handler=_cmd_policy_show)
    return parser


def _key_from_env(name: Optional[str]) -> Optional[bytes]:
    if not name:
        return None
    value = os.getenv(name)
    if value is None:
        raise LedgerError(
            f"The environment variable '{name}' is not set.",
            "signing and signature verification need a shared secret, never a command-line value.",
            f"export {name}=<secret> in the process that records or verifies evidence.",
        )
    key = value.encode("utf-8")
    if len(key) < 16:
        raise LedgerError(
            "The HMAC key is shorter than 16 bytes.",
            "a short key is cheap to guess and makes the signature decorative.",
            "use at least 16 random bytes, for example 32 hex characters.",
        )
    return key


def _load_state(path: Path, key: Optional[bytes]) -> LedgerState:
    return Ledger(path, key).inspect()


def _metadata(text: Optional[str]) -> Dict[str, Any]:
    if text is None:
        return {}
    source = "the argument"
    if text.startswith("@"):
        path = Path(text[1:])
        source = str(path)
        try:
            text = path.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeError) as exc:
            raise ValidationError(
                f"Metadata file '{path}' could not be read: {exc}.",
                "the event needs its metadata before it can be hashed.",
                "check the path and permissions, then retry.",
            ) from exc
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValidationError(
            f"Metadata from {source} is not valid JSON: {exc.msg} (line {exc.lineno}).",
            "metadata is stored as canonical JSON and covered by the record hash.",
            "pass a JSON object or a path prefixed with @.",
        ) from exc
    if not isinstance(value, dict):
        raise ValidationError(
            "Metadata must be a JSON object.",
            "named evidence fields are needed for policy checks and review.",
            "pass an object such as {\"amount\": 2500}.",
        )
    return value


def _policy_reference(policy: Optional[Policy]) -> Optional[Dict[str, str]]:
    return policy.reference() if policy is not None else None


def _cmd_record(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy) if args.policy else None
    values: Dict[str, Any] = {
        "outcome": args.outcome,
        "target": args.target,
        "metadata": _metadata(args.metadata),
        "policy": _policy_reference(policy),
    }
    if args.ts:
        values["ts"] = normalize_timestamp(args.ts)
    event = Event.create(args.actor, args.action, **values)
    envelope = Ledger(args.ledger, _key_from_env(args.hmac_key_env)).append(event)
    if args.json:
        print(json.dumps(envelope, indent=2, sort_keys=True))
    else:
        print(f"Recorded seq={envelope['seq']} actor={event.actor} action={event.action}")
        print(f"Hash: {envelope['hash']}")
        if policy is not None:
            print(f"Policy: {policy.name} ({policy.digest[:12]}...)")
    return 0


def _value(row: Mapping[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        value = row.get(name)
        if value is not None and value != "":
            return value
    return default


def _read_source(path_text: str) -> str:
    if path_text == "-":
        return sys.stdin.read()
    path = Path(path_text)
    try:
        return path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as exc:
        raise ValidationError(
            f"Input '{path}' could not be read: {exc}.",
            "ingest needs the producer's JSONL file before any event is written.",
            "check the path and permissions, then retry.",
        ) from exc


def _parse_ingest(text: str, input_format: str, actor: Optional[str],
                  policy_ref: Optional[Dict[str, str]]) -> List[Event]:
    return parse_event_stream(text, input_format, actor_default=actor, policy_ref=policy_ref)


def _cmd_ingest(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy) if args.policy else None
    events = _parse_ingest(_read_source(args.file), args.input_format, args.actor,
                           _policy_reference(policy))
    key = _key_from_env(args.hmac_key_env)  # aikit:allow-secret the value is an environment indirection, not a credential
    ledger = Ledger(args.ledger, key)
    envelopes = [ledger.append(event) for event in events]
    if args.json:
        print(json.dumps({
            "recorded": len(envelopes),
            "head": envelopes[-1]["hash"],
            "policy": _policy_reference(policy),
        }, indent=2, sort_keys=True))
    else:
        print(f"Recorded {len(envelopes)} event(s) in {args.ledger}")
        print(f"Head: {envelopes[-1]['hash']}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    state = _load_state(args.ledger, _key_from_env(args.hmac_key_env))
    verification = state.verification
    errors = list(verification.errors)
    anchors_checked = None
    if args.anchors is not None:
        anchor_state = AnchorJournal(args.anchors).inspect()
        anchors_checked = len(anchor_state.records)
        if not anchor_state.verification.ok:
            for error in anchor_state.verification.errors:
                errors.append(f"Anchor journal error: {error}")
        for anchor in anchor_state.records:
            seq = anchor["seq"]
            head = anchor["head"]
            if seq >= len(state.records):
                errors.append(
                    f"Anchor seq {seq} exceeds ledger length ({len(state.records)} record(s)) - tail truncated"
                )
            elif state.records[seq]["hash"] != head:
                errors.append(
                    f"Anchor seq {seq} head {head} does not match ledger record hash {state.records[seq]['hash']}"
                )
    ok = verification.ok and not errors
    if args.json:
        payload = verification.to_dict()
        payload["ok"] = ok
        payload["errors"] = errors
        if anchors_checked is not None:
            payload["anchors"] = anchors_checked
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif ok:
        print(f"Ledger OK: {verification.records} record(s), head {verification.head}")
        print(f"Signed: {'yes' if verification.signed else 'no'}; "
              f"signature checked: {'yes' if verification.key_checked else 'no'}")
        if anchors_checked is not None:
            print(f"Anchors OK: {anchors_checked} anchor(s) verified against ledger")
    else:
        print(f"Ledger FAILED: {len(errors)} problem(s) "
              f"in {verification.records} parsed record(s)")
        for error in errors:
            print(f"  - {error}")
    return 0 if ok else 1


def _cmd_anchor(args: argparse.Namespace) -> int:
    if args.hmac_key_env and not args.key_id:
        raise ValidationError(
            "An HMAC key requires --key-id.",
            "the key identifier pairs with the signing key so rotations are traceable without exposing secrets.",
            "pass --key-id ID alongside --hmac-key-env.",
        )
    if args.key_id and not args.hmac_key_env:
        raise ValidationError(
            "--hmac-key-env is required when --key-id is passed.",
            "a key id names the key used to sign the ledger records.",
            "pass --hmac-key-env VAR alongside --key-id.",
        )
    key = _key_from_env(args.hmac_key_env)
    state = _load_state(args.ledger, key)
    if not state.verification.ok:
        print(f"Ledger FAILED: {len(state.verification.errors)} problem(s) "
              f"in {state.verification.records} parsed record(s)")
        for error in state.verification.errors:
            print(f"  - {error}")
        return 1
    if not state.records:
        raise ValidationError(
            "The ledger has no records to anchor.",
            "an anchor commits to an existing ledger head.",
            "record at least one event before anchoring.",
        )
    ledger_label = args.ledger_label or args.ledger.name
    latest = state.records[-1]
    journal = AnchorJournal(args.anchors)
    record = journal.append(
        ledger=ledger_label,
        seq=latest["seq"],
        head=state.verification.head,
        key_id=args.key_id,
    )
    if args.json:
        print(json.dumps(record, indent=2, sort_keys=True))
    else:
        print(f"Anchored seq={record['seq']} head={record['head']} in {args.anchors}")
        print(f"Anchor hash: {record['hash']}")
    return 0


def _review(records: Sequence[Mapping[str, Any]], policy: Policy) -> List[Finding]:
    findings = review_events(policy, records) + drift_findings(policy, records)
    return sorted(findings, key=lambda item: (item.seq, item.rule_id))


def _cmd_review(args: argparse.Namespace) -> int:
    if args.policy is None:
        raise ValidationError(
            "review needs --policy.",
            "findings are defined by a policy, not by the ledger alone.",
            "pass --policy examples/policy.json.",
        )
    state = _load_state(args.ledger, _key_from_env(args.hmac_key_env))
    policy = load_policy(args.policy)
    findings = _review(state.records, policy)
    if args.json:
        print(json.dumps({
            "policy": policy.reference(),
            "ledger": {
                "verified": state.verification.ok,
                "records": state.verification.records,
                "head": state.verification.head,
                "errors": list(state.verification.errors),
            },
            "findings": [finding.to_dict() for finding in findings],
        }, indent=2, sort_keys=True))
    else:
        print(f"Policy {policy.name} ({policy.digest[:12]}...)")
        print(f"Chain: {'OK' if state.verification.ok else 'FAILED'}; "
              f"records: {state.verification.records}; findings: {len(findings)}")
        for finding in findings:
            print(f"  - seq {finding.seq} {finding.actor} {finding.action}: "
                  f"{finding.effect} ({finding.rule_id}) - {finding.reason}")
    return 0 if state.verification.ok and not findings else 1


def _cmd_report(args: argparse.Namespace) -> int:
    state = _load_state(args.ledger, _key_from_env(args.hmac_key_env))
    policy = load_policy(args.policy) if args.policy else None
    pack = build_pack(str(args.ledger), state, policy)
    if args.out is not None:
        write_report(pack, args.out, args.report_format)
        print(f"Wrote {args.out} ({pack['verdict']}, {state.verification.records} record(s))")
    elif args.report_format == "json":
        print(json.dumps(pack, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print(render_markdown(pack))
    return 0 if state.verification.ok else 1


def _cmd_demo(args: argparse.Namespace) -> int:
    directory = args.out or Path(tempfile.mkdtemp(prefix="assay-demo-"))
    result = run_demo(directory)
    payload = {
        "directory": str(result.directory),
        "ledger": str(result.ledger_path),
        "policy": result.policy.reference(),
        "records": result.state.verification.records,
        "verified": result.state.verification.ok,
        "findings": [finding.to_dict() for finding in result.findings],
        "evidence_markdown": str(result.markdown_path),
        "evidence_json": str(result.json_path),
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Ledger: {result.ledger_path} "
              f"({result.state.verification.records} records, "
              f"chain {'verified' if result.state.verification.ok else 'FAILED'})")
        print(f"Policy: {result.policy.name} ({result.policy.digest[:12]}...)")
        print(f"Findings: {len(result.findings)}")
        for finding in result.findings:
            print(f"  - seq {finding.seq} {finding.action}: "
                  f"{finding.rule_id} - {finding.reason}")
        print(f"Evidence: {result.markdown_path}")
        print(f"          {result.json_path}")
    return 0 if result.state.verification.ok else 1


def _cmd_policy_list(args: argparse.Namespace) -> int:
    packs = list_packs()
    if args.json:
        result = []
        for name in packs:
            p = load_pack(name)
            result.append({
                "pack": name,
                "name": p.name,
                "digest": p.digest,
                "rules": len(p.rules),
                "default": p.default,
            })
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"Available policy packs ({len(packs)}):")
        for name in packs:
            p = load_pack(name)
            print(f"  - {name:<20} {p.name:<30} ({len(p.rules)} rules, digest: {p.digest[:12]}...)")
    return 0


def _cmd_policy_show(args: argparse.Namespace) -> int:
    policy = load_policy(args.name)
    if args.json:
        print(json.dumps(policy.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"Policy: {policy.name}")
        print(f"Digest: {policy.digest}")
        print(f"Default: {policy.default}")
        print(f"Rules ({len(policy.rules)}):")
        for rule in policy.rules:
            details = []
            if rule.amount_over is not None:
                details.append(f"amount > {rule.amount_over:g}")
            if rule.amount_under is not None:
                details.append(f"amount < {rule.amount_under:g}")
            if rule.metadata:
                details.append(f"metadata={json.dumps(dict(rule.metadata), sort_keys=True)}")
            suffix = f" ({', '.join(details)})" if details else ""
            print(f"  - [{rule.effect:<16}] {rule.id:<26} action={rule.action}{suffix}")
    return 0


def _report_error(error: AssayError) -> int:
    print(f"Error: {error.message}", file=sys.stderr)
    print(f"Why: {error.why}", file=sys.stderr)
    print(f"Fix: {error.fix}", file=sys.stderr)
    return error.exit_code


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Parse arguments, run one command and return 0, 1 or 2."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        return args.handler(args)
    except AssayError as error:
        return _report_error(error)
    except BrokenPipeError:
        return 0
    except OSError as error:
        print(f"Error: {error}", file=sys.stderr)
        print("Why: the filesystem operation needed by this command failed.", file=sys.stderr)
        print("Fix: check the path, permissions and free space, then retry.", file=sys.stderr)
        return 2


def entry() -> None:
    """Console-script entry point."""
    raise SystemExit(main())
