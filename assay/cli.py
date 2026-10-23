"""Command-line interface for recording, verifying and reviewing agent evidence."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .demo import run_demo
from .errors import AssayError, LedgerError, ValidationError
from .ledger import Ledger, LedgerState
from .model import OUTCOMES, Event, normalize_timestamp
from .policy import Finding, Policy, drift_findings, load_policy, review_events
from .report import build_pack, render_markdown, write_report
from .version import VERSION

DEFAULT_LEDGER = Path(".assay") / "ledger.jsonl"


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
    parser.add_argument("--policy", type=Path, help="policy JSON file")


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
    ingest.add_argument("--format", dest="input_format", choices=("generic", "mcp"),
                        default="generic", help="adapter for the incoming records")
    ingest.add_argument("--actor", help="fallback actor when a record omits one")
    _add_policy(ingest)
    _add_ledger(ingest)
    ingest.add_argument("--json", action="store_true", help="print a machine-readable summary")
    ingest.set_defaults(handler=_cmd_ingest)

    verify = commands.add_parser("verify", help="verify the hash chain and signatures")
    _add_ledger(verify)
    verify.add_argument("--json", action="store_true", help="print the verification as JSON")
    verify.set_defaults(handler=_cmd_verify)

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


def _generic_event(row: Mapping[str, Any], actor_default: Optional[str],
                   policy_ref: Optional[Dict[str, str]]) -> Event:
    actor = _value(row, "actor", "agent", "actor_id", default=actor_default)
    action = _value(row, "action", "tool", "name")
    if not isinstance(actor, str) or not actor.strip():
        raise ValidationError(
            "An ingested record has no actor.",
            "every action must name the agent or principal that performed it.",
            "add an actor field or pass --actor as the fallback.",
        )
    if not isinstance(action, str) or not action.strip():
        raise ValidationError(
            "An ingested record has no action or tool name.",
            "a record without an action cannot be audited or matched by a policy.",
            "add action/tool/name, or fix the producer mapping.",
        )
    raw_outcome = _value(row, "outcome", "status", default="success")
    outcome = raw_outcome.lower() if isinstance(raw_outcome, str) else "success"
    if outcome not in OUTCOMES:
        outcome = "success"
    metadata = _value(row, "metadata", "arguments", "input", default={})
    ts = _value(row, "ts", "timestamp", "time")
    return Event.create(
        actor, action,
        outcome=outcome,
        target=_value(row, "target", "resource", "destination", default=""),
        metadata=metadata,
        policy=policy_ref,
        **({"ts": normalize_timestamp(ts)} if ts is not None else {}),
    )


def _mcp_event(row: Mapping[str, Any], actor_default: Optional[str],
               policy_ref: Optional[Dict[str, str]]) -> Optional[Event]:
    method = row.get("method")
    if method is not None and method != "tools/call":
        return None
    params = row.get("params")
    params = params if isinstance(params, Mapping) else {}
    action = params.get("name") or row.get("tool")
    if not isinstance(action, str) or not action.strip():
        raise ValidationError(
            "An MCP tools/call record has no tool name.",
            "the tool name is the audited action.",
            "fix the producer or use --format generic with an explicit mapping.",
        )
    actor = _value(row, "actor", "agent", default=actor_default)
    if not isinstance(actor, str) or not actor.strip():
        raise ValidationError(
            "An MCP record has no actor.",
            "tool calls need a principal, even when the server log omits one.",
            "pass --actor for the session.",
        )
    result = row.get("result")
    outcome = "error" if isinstance(result, Mapping) and result.get("isError") else "success"
    metadata = params.get("arguments")
    if not isinstance(metadata, Mapping):
        metadata = {}
    ts = _value(row, "ts", "timestamp", "time")
    return Event.create(
        actor, action,
        outcome=outcome,
        metadata=dict(metadata),
        policy=policy_ref,
        **({"ts": normalize_timestamp(ts)} if ts is not None else {}),
    )


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
    events: List[Event] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValidationError(
                f"Input line {number} is not valid JSON: {exc.msg}.",
                "the whole file is validated before any event is appended.",
                "fix the producer output and retry; nothing was written.",
            ) from exc
        if not isinstance(row, Mapping):
            raise ValidationError(
                f"Input line {number} is not a JSON object.",
                "each JSONL line must describe one action.",
                "fix the producer output and retry; nothing was written.",
            )
        if input_format == "mcp":
            event = _mcp_event(row, actor, policy_ref)
        else:
            event = _generic_event(row, actor, policy_ref)
        if event is not None:
            events.append(event)
    if not events:
        raise ValidationError(
            "No events were found in the input.",
            "an empty ingest would produce an empty evidence trail.",
            "check the file and adapter, then retry.",
        )
    return events


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
    if args.json:
        print(json.dumps(verification.to_dict(), indent=2, sort_keys=True))
    elif verification.ok:
        print(f"Ledger OK: {verification.records} record(s), head {verification.head}")
        print(f"Signed: {'yes' if verification.signed else 'no'}; "
              f"signature checked: {'yes' if verification.key_checked else 'no'}")
    else:
        print(f"Ledger FAILED: {len(verification.errors)} problem(s) "
              f"in {verification.records} parsed record(s)")
        for error in verification.errors:
            print(f"  - {error}")
    return 0 if verification.ok else 1


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
