# Codebase Map & Symbol Catalog 🗺️

> **AUTO-GENERATED & VERIFIED BY `scripts/update_knowledge_base.py`**
> This document provides an automated, up-to-date registry of all modules, classes, and exported functions across this repository.

---

## 📊 Codebase Metrics
- **Total Python Modules**: `22`
- **Total Classes**: `36`
- **Total Top-Level Functions**: `75`
- **Total Class Methods**: `158`
- **Total Source Lines**: `3799`

---

## 📦 Modules & Exported Symbols

### [`assay/__init__.py`](assay/__init__.py)
> *Assay: tamper-evident audit evidence for AI agents.*

**Size**: `37` lines (`741` bytes)

---

### [`assay/__main__.py`](assay/__main__.py)
> *Allow `python -m assay` to run the command line.*

**Size**: `6` lines (`119` bytes)

---

### [`assay/adapters.py`](assay/adapters.py)
> *Adapters that transform event telemetry from major agent frameworks into Assay events.*

**Size**: `318` lines (`13926` bytes)

**Functions:**
- `def _value(row, *names, default)`
- `def _as_dict(value)`
- `def generic_event(row, actor_default, policy_ref)` - *Transform standard generic JSON into an Assay Event.*
- `def mcp_event(row, actor_default, policy_ref)` - *Transform Model Context Protocol (MCP) JSON-RPC messages into an Event.*
- `def openai_event(row, actor_default, policy_ref)` - *Transform OpenAI tool calls and assistant execution telemetry into an Event.*
- `def langgraph_event(row, actor_default, policy_ref)` - *Transform LangChain and LangGraph node/tool event records into an Event.*
- `def crewai_event(row, actor_default, policy_ref)` - *Transform CrewAI tool execution and agent action dictionaries into an Event.*
- `def adapt_event(format_name, row, actor_default, policy_ref)` - *Transform a dictionary from a named framework into an Event.*
- `def parse_event_stream(text, format_name, actor_default, policy_ref)` - *Parse JSONL stream using the selected framework adapter.*

---

### [`assay/anchor.py`](assay/anchor.py)
> *Append-only anchor journal that commits to a ledger head.*

**Size**: `336` lines (`13024` bytes)

**Classes:**
- `class Anchor` - *One immutable commitment to a ledger seq and hash.*
  - Method `.to_dict()`
  - Method `.from_dict(value)`
- `class AnchorVerification` - *The outcome of walking the whole anchor journal once.*
  - Method `.to_dict()`
- `class AnchorState` - *Anchor records and their verification, read in one pass.*
  - Property `.latest`
- `class AnchorJournal` - *Persist anchors in a JSONL file whose every record commits to its predecessor.*
  - Method `.__init__(path)`
  - Method `.append(*, ledger, seq, head, key_id, created_at)` - *Append one anchor and return the stored record.*
  - Method `.inspect()` - *Read and verify every anchor; malformed or tampered records become findings.*
  - Method `._tail()` - *The previous anchor hash and seq, rejecting a corrupt last line.*

**Functions:**
- `def anchor_payload(*, schema, ledger, seq, head, created_at, key_id, prev)` - *The exact bytes an anchor hash covers; documented in docs/SECURITY.md.*
- `def anchor_hash(*, schema, ledger, seq, head, created_at, key_id, prev)` - *SHA-256 over the canonical anchor payload.*
- `def _digest(value, name)`
- `def _sequence(value)`
- `def _ledger_label(value)`
- `def _key_identifier(value)`
- `def _created_at(value)`
- `def _json_line(value)`

---

### [`assay/cli.py`](assay/cli.py)
> *Command-line interface for recording, verifying and reviewing agent evidence.*

**Size**: `441` lines (`18667` bytes)

**Classes:**
- `class Parser` - *Turn argument errors into the Assay triad instead of an unlabelled usage dump.*
  - Method `.error(message)`

**Functions:**
- `def _add_ledger(parser)`
- `def _add_policy(parser)`
- `def build_parser()` - *The complete command surface; every subcommand returns an exit code.*
- `def _key_from_env(name)`
- `def _load_state(path, key)`
- `def _metadata(text)`
- `def _policy_reference(policy)`
- `def _cmd_record(args)`
- `def _value(row, *names, default)`
- `def _read_source(path_text)`
- `def _parse_ingest(text, input_format, actor, policy_ref)`
- `def _cmd_ingest(args)`
- `def _cmd_verify(args)`
- `def _cmd_anchor(args)`
- `def _review(records, policy)`
- `def _cmd_review(args)`
- `def _cmd_report(args)`
- `def _cmd_demo(args)`
- `def _report_error(error)`
- `def main(argv)` - *Parse arguments, run one command and return 0, 1 or 2.*
- `def entry()` - *Console-script entry point.*

---

### [`assay/demo.py`](assay/demo.py)
> *A deterministic treasury-agent scenario that shows the product in one command.*

**Size**: `77` lines (`3101` bytes)

**Classes:**
- `class DemoResult` - *Everything the demo wrote, so tests and the CLI share one contract.*

**Functions:**
- `def _events()`
- `def run_demo(directory)` - *Create a policy, a signed-off chain, findings and both evidence packs.*

---

### [`assay/errors.py`](assay/errors.py)
> *Failures that carry the Error/Why/Fix triad printed by the command line.*

**Size**: `24` lines (`717` bytes)

**Classes:**
- `class AssayError` - *A user-actionable failure; `exit_code` follows the 0/1/2 contract.*
  - Method `.__init__(message, why, fix, exit_code)`
- `class ValidationError` - *An event or policy document breaks the declared contract.*
- `class LedgerError` - *The ledger cannot be read, appended or verified.*
- `class AnchorError` - *The anchor journal cannot be read, appended or verified.*

---

### [`assay/ledger.py`](assay/ledger.py)
> *Append-only hash-chained ledger with optional HMAC signing.*

**Size**: `220` lines (`8932` bytes)

**Classes:**
- `class Verification` - *The outcome of walking the whole chain once.*
  - Method `.to_dict()`
- `class LedgerState` - *Records and their verification, read in one pass.*
- `class Ledger` - *Persist events in a JSONL file whose every record commits to its predecessor.*
  - Method `.__init__(path, key)`
  - Method `.append(event)` - *Append one event and return the stored envelope.*
  - Method `.inspect()` - *Read and verify every record; malformed or tampered records become findings.*
  - Method `._tail()` - *The next sequence number and previous hash, rejecting a corrupt last line.*

**Functions:**
- `def record_payload(seq, prev, event)` - *The exact bytes a record hash covers; documented in docs/SECURITY.md.*
- `def record_hash(seq, prev, event)` - *SHA-256 over the canonical record payload.*
- `def record_mac(key, seq, prev, event)` - *HMAC-SHA256 over the same payload, keyed by a secret the verifier holds.*
- `def _json_line(envelope)`

---

### [`assay/model.py`](assay/model.py)
> *Event contract and canonical serialization for the evidence ledger.*

**Size**: `248` lines (`10102` bytes)

**Classes:**
- `class Event` - *One agent action, normalized and validated before hashing.*
  - Method `.__post_init__()`
  - Method `.create(actor, action, **values)` - *Build an event from CLI or adapter input with the documented defaults.*
  - Method `.from_dict(value)` - *Parse a stored event, refusing unknown fields instead of silently dropping them.*
  - Method `.to_dict()` - *The canonical stored form; `None` fields are omitted.*

**Functions:**
- `def canonical_bytes(value)` - *Deterministic UTF-8 JSON used for every digest in the ledger.*
- `def utc_now()` - *Current UTC time in the ISO-8601 form stored in events.*
- `def normalize_timestamp(value)` - *Accept an ISO-8601 string or Unix seconds and return a UTC ISO-8601 string.*
- `def _text(value, name, limit, required)`
- `def _metadata(value)`
- `def _policy_ref(value)`

---

### [`assay/policy.py`](assay/policy.py)
> *Declarative agent policy evaluation and retrospective findings.*

**Size**: `345` lines (`13879` bytes)

**Classes:**
- `class Rule` - *One first-match policy rule; `*` is the only glob supported in `action`.*
  - Method `.match(event)` - *Whether the rule applies, a reviewable reason, and whether the amount is unverifiable.*
  - Method `.to_dict()`
- `class Decision` - *The effective rule and reason for one event.*
- `class Finding` - *A policy violation or an unverifiable requirement, tied to its ledger position.*
  - Method `.to_dict()`
- `class Policy` - *A validated policy document with a stable digest.*
  - Method `.evaluate(event)` - *First matching rule wins; the default applies when none matches.*
  - Method `.review(event, seq)` - *Return a finding when the action is denied or lacks a required approval.*
  - Method `.reference()` - *The compact policy reference stored with each event.*
  - Method `.to_dict()`

**Functions:**
- `def _approved(event)`
- `def _finite(value, name)`
- `def _parse_rule(value, position)`
- `def parse_policy(value)` - *Validate a decoded policy document and compute its digest.*
- `def load_policy(path)` - *Read and validate a policy file with an actionable failure triad.*
- `def review_events(policy, records)` - *Evaluate every stored event, attaching its ledger sequence to each finding.*
- `def drift_findings(policy, records)` - *Flag events recorded under a different policy digest than the one under review.*

---

### [`assay/report.py`](assay/report.py)
> *Self-contained evidence packs in Markdown and JSON.*

**Size**: `239` lines (`9105` bytes)

**Functions:**
- `def _event(envelope)`
- `def _finding_summary(findings)`
- `def build_pack(ledger_name, state, policy)` - *Assemble the JSON evidence pack from verified records and an optional policy.*
- `def _cell(value, limit)`
- `def _bullets(values)`
- `def render_markdown(pack)` - *Render the pack as a reviewable Markdown document.*
- `def write_report(pack, path, fmt)` - *Write Markdown or JSON through the atomic storage helper.*

---

### [`assay/storage.py`](assay/storage.py)
> *Durable file primitives shared by the ledger and generated reports.*

**Size**: `73` lines (`2515` bytes)

**Functions:**
- `def read_lines(path)` - *Yield the file's lines without terminators; a missing file raises OSError.*
- `def last_nonempty_line(path, chunk_size)` - *The last non-empty line, read from the tail instead of scanning the whole ledger.*
- `def append_line(path, line)` - *Append one line and fsync it so a confirmed record survives power loss.*
- `def write_text_atomic(path, content)` - *Write text through a same-directory temp file, fsync and atomic replace.*
- `def _fsync_directory(path)` - *Flush the directory entry on POSIX; Windows has no directory handle to sync.*

---

### [`assay/version.py`](assay/version.py)
> *Single source of truth for the package version.*

**Size**: `3` lines (`73` bytes)

---

### [`tests/__init__.py`](tests/__init__.py)
> *Regression suite for Assay.*

**Size**: `1` lines (`34` bytes)

---

### [`tests/test_adapters.py`](tests/test_adapters.py)
> *Agent framework adapter tests for MCP, OpenAI, LangGraph, and CrewAI.*

**Size**: `248` lines (`8720` bytes)

**Classes:**
- `class GenericAdapterTests`
  - Method `.test_standard_keys()`
  - Method `.test_alternate_field_names()`
  - Method `.test_missing_actor_raises()`
  - Method `.test_actor_fallback()`
- `class McpAdapterTests`
  - Method `.test_tools_call_event()`
  - Method `.test_non_tool_call_returns_none()`
  - Method `.test_error_result()`
- `class OpenAiAdapterTests`
  - Method `.test_tool_call_with_string_arguments()`
  - Method `.test_tool_call_with_dict_arguments()`
  - Method `.test_chat_completion_tool_call_item()`
  - Method `.test_error_status()`
- `class LangGraphAdapterTests`
  - Method `.test_on_tool_end_event()`
  - Method `.test_tool_message_format()`
  - Method `.test_node_execution_format()`
  - Method `.test_error_event()`
- `class CrewAiAdapterTests`
  - Method `.test_agent_tool_execution()`
  - Method `.test_action_input_format()`
- `class AdapterDispatcherTests`
  - Method `.test_known_adapters()`
  - Method `.test_unknown_format_raises()`
  - Method `.test_parse_event_stream()`

---

### [`tests/test_anchor.py`](tests/test_anchor.py)
> *Anchor record, journal chain and tamper detection tests.*

**Size**: `202` lines (`7787` bytes)

**Classes:**
- `class AnchorPayloadTests`
  - Method `.test_payload_is_canonical_json()`
  - Method `.test_hash_covers_every_field()`
  - Method `.test_published_anchor_test_vector()`
- `class AnchorJournalTests`
  - Method `.setUp()`
  - Method `._rewrite(transform)`
  - Method `.test_append_creates_a_contiguous_anchor_chain()`
  - Method `.test_duplicate_seq_is_allowed()`
  - Method `.test_seq_cannot_move_backwards()`
  - Method `.test_head_must_be_a_lowercase_sha256()`
  - Method `.test_negative_seq_is_refused()`
  - Method `.test_key_id_is_an_identifier_or_absent()`
  - Method `.test_created_at_is_normalized()`
  - Method `.test_tampered_anchor_is_detected()`
  - Method `.test_deleted_middle_anchor_is_detected()`
  - Method `.test_unknown_field_is_refused()`
  - Method `.test_unsupported_schema_is_refused()`
  - Method `.test_corrupt_tail_refuses_append()`
  - Method `.test_missing_journal_raises()`

**Functions:**
- `def _append(journal, seq, head, ledger, key_id, created_at)`

---

### [`tests/test_cli.py`](tests/test_cli.py)
> *End-to-end command-line tests through `main`, without spawning processes.*

**Size**: `388` lines (`18053` bytes)

**Classes:**
- `class CliTests`
  - Method `.setUp()`
  - Method `._run(*args)`
  - Method `._record(action, **extra)`
  - Method `.test_record_and_verify()`
  - Method `.test_tampered_ledger_exits_one()`
  - Method `.test_record_attaches_policy_reference()`
  - Method `.test_review_exit_codes()`
  - Method `.test_report_writes_markdown_and_json()`
  - Method `.test_ingest_generic()`
  - Method `.test_ingest_mcp()`
  - Method `.test_ingest_openai()`
  - Method `.test_ingest_langgraph()`
  - Method `.test_ingest_crewai()`
  - Method `.test_ingest_validates_before_writing()`
  - Method `.test_usage_error_uses_triad()`
  - Method `.test_missing_key_environment_variable()`
  - Method `.test_signed_round_trip()`
  - Method `.test_demo_writes_evidence()`
  - Method `.test_anchor_commits_to_the_ledger_head()`
  - Method `.test_anchor_refuses_a_broken_ledger()`
  - Method `.test_anchor_refuses_an_empty_ledger()`
  - Method `.test_anchor_key_id_pairs_with_signing()`
  - Method `.test_anchor_json_reports_the_record()`
  - Method `.test_verify_with_anchors_succeeds()`
  - Method `.test_verify_anchors_detects_tail_truncation()`
  - Method `.test_verify_anchors_detects_rewritten_chain()`
  - Method `.test_verify_anchors_detects_tampered_anchor_journal()`
  - Method `.test_verify_missing_anchors_is_usage_error()`
  - Method `.test_missing_ledger_is_usage_error()`

---

### [`tests/test_launchers.py`](tests/test_launchers.py)
> *Launcher contract checks; execution is covered by the manual smoke run and CI.*

**Size**: `29` lines (`1030` bytes)

**Classes:**
- `class LauncherTests`
  - Method `.test_windows_launcher_checks_python_and_defaults_to_demo()`
  - Method `.test_posix_launcher_checks_candidates_and_defaults_to_demo()`
  - Method `.test_macos_launcher_delegates()`

---

### [`tests/test_ledger.py`](tests/test_ledger.py)
> *Hash chain, tamper detection and signing tests.*

**Size**: `152` lines (`6393` bytes)

**Classes:**
- `class LedgerTests`
  - Method `.setUp()`
  - Method `._write_events(count, key)`
  - Method `.test_append_creates_a_contiguous_chain()`
  - Method `.test_tail_reads_a_long_last_line()`
  - Method `.test_append_after_a_long_record()`
  - Method `.test_hashes_are_deterministic()`
  - Method `.test_published_test_vector()`
  - Method `.test_tampered_event_is_detected()`
  - Method `.test_deleted_middle_is_detected()`
  - Method `.test_malformed_line_is_detected()`
  - Method `.test_signed_chain_verifies_with_key()`
  - Method `.test_signed_chain_without_key_is_flagged_unchecked()`
  - Method `.test_wrong_key_is_detected()`
  - Method `.test_unsigned_chain_fails_when_a_key_is_supplied()`
  - Method `.test_mixed_signing_is_detected()`
  - Method `.test_append_refuses_a_corrupt_tail()`
  - Method `.test_missing_ledger_raises()`

**Functions:**
- `def _event(number)`

---

### [`tests/test_model.py`](tests/test_model.py)
> *Event contract and canonical JSON tests.*

**Size**: `106` lines (`4113` bytes)

**Classes:**
- `class CanonicalJsonTests`
  - Method `.test_sorted_keys_and_unicode_are_stable()`
  - Method `.test_nested_order_does_not_change_bytes()`
- `class TimestampTests`
  - Method `.test_unix_seconds_become_utc()`
  - Method `.test_offset_is_normalized_to_utc()`
  - Method `.test_naive_timestamp_is_refused()`
  - Method `.test_non_date_is_refused()`
  - Method `.test_out_of_range_epoch_is_refused()`
- `class EventTests`
  - Method `.test_defaults_and_round_trip()`
  - Method `.test_empty_actor_is_refused()`
  - Method `.test_control_character_is_refused()`
  - Method `.test_unknown_outcome_is_refused()`
  - Method `.test_non_object_metadata_is_refused()`
  - Method `.test_nan_metadata_is_refused()`
  - Method `.test_unknown_stored_field_is_refused()`
  - Method `.test_missing_stored_field_is_refused()`
  - Method `.test_unsupported_schema_is_refused()`
  - Method `.test_policy_reference_digest_shape()`
  - Method `.test_json_serializable_dict()`

---

### [`tests/test_policy.py`](tests/test_policy.py)
> *Policy parsing, matching and finding tests.*

**Size**: `198` lines (`8319` bytes)

**Classes:**
- `class PolicyEvaluationTests`
  - Method `.test_default_allow()`
  - Method `.test_deny_glob()`
  - Method `.test_require_approval()`
  - Method `.test_amount_over_threshold()`
  - Method `.test_amount_under_threshold()`
  - Method `.test_amount_band()`
  - Method `.test_unverifiable_amount_is_denied()`
  - Method `.test_metadata_condition()`
  - Method `.test_first_match_wins()`
  - Method `.test_default_deny()`
  - Method `.test_digest_stable_and_reference()`
  - Method `.test_rule_without_amount_condition_matches()`
- `class PolicyValidationTests`
  - Method `.test_invalid_documents_are_refused()`
  - Method `.test_load_policy()`
- `class PolicyReviewTests`
  - Method `._records()`
  - Method `.test_review_events_attaches_sequence()`
  - Method `.test_drift_findings()`
  - Method `.test_no_findings_for_compliant_records()`

**Functions:**
- `def _event(action, **metadata)`
- `def _document(**overrides)`

---

### [`tests/test_report.py`](tests/test_report.py)
> *Evidence pack assembly and rendering tests.*

**Size**: `108` lines (`4325` bytes)

**Classes:**
- `class ReportTests`
  - Method `.setUp()`
  - Method `._state(actions)`
  - Method `.test_review_verdict_and_markdown()`
  - Method `.test_pass_verdict_without_findings()`
  - Method `.test_fail_verdict_on_broken_chain()`
  - Method `.test_no_policy_is_allowed()`
  - Method `.test_markdown_escapes_table_cells()`
  - Method `.test_write_json_and_markdown()`
  - Method `.test_unknown_format_is_refused()`

**Functions:**
- `def _event(action, **metadata)`
- `def _policy(rules)`

---
