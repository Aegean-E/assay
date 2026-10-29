# Changelog

All notable changes to Assay are documented here. The format follows Keep a Changelog and the
project uses semantic versioning.

## [Unreleased]

### Changed

- New versions are licensed under Aegean License 1.1 (AL-1.1).
- Bumped the version to 0.2.0.

### Added

- Head anchoring journal (`assay.anchor`, `assay anchor`) committing ledger head hashes to an append-only journal.
- Offline cross-verification (`assay verify --anchors <journal>`) catching tail truncation and whole-chain rewrites.
- Mandatory `--key-id` pairing with `--hmac-key-env` to track key rotations without leaking credentials.
- Published anchor test vector and updated threat model in `docs/SECURITY.md`.
- Zero-dependency framework adapters (`assay.adapters`) for MCP JSON-RPC, OpenAI tool calls, LangGraph/LangChain telemetry, and CrewAI actions.
- Multi-framework stream ingestion via `assay ingest --format <generic|mcp|openai|langgraph|crewai>`.
- Curated guardrail policy packs (`assay.packs`) for `payments`, `production_change`, `customer_data`, and `support_agent`.
- Direct `pack:<name>` policy resolution across all policy-aware CLI commands and Python APIs.
- CLI policy inspection commands (`assay policy list` and `assay policy show`).
- Architecture Decision Records ADR-006, ADR-007, and ADR-008 in `.aikit/decisions.md`.

### Fixed

- Generic ingestion now rejects an unknown outcome value instead of silently recording it as `success`.
- Ledger appends now refuse a malformed tail hash or a negative sequence instead of extending a corrupt chain.

## [0.1.0] - 2026-10-23

### Added

- Canonical, versioned agent event contract with strict validation and UTC timestamps.
- Append-only JSONL ledger with contiguous SHA-256 hash chain, fsynced appends and a fast tail read.
- Optional HMAC-SHA256 signing with the key supplied only through a named environment variable.
- First-match policy engine with action globs, exact metadata conditions, exclusive amount
  thresholds, policy digests and `policy_drift` findings.
- `record`, `ingest` (generic and MCP), `verify`, `review`, `report` and `demo` commands.
- Self-contained JSON evidence packs and reviewer-oriented Markdown packs with policy rules.
- A verified five-event treasury-agent demo that produces two findings.
- Licensing, packaging, console script, Windows/POSIX/macOS launchers and a
  three-OS CI matrix.
- Business brief, compliance mapping, threat model, launch/sales kit and contribution/security
  policies.

### Verification

- 73 unit and integration tests pass.
- AIKit Phase 4 gates pass: test, hygiene, guidelines and secret scan.
- Wheel installation, console-script execution and all three launchers were smoke-tested.
- The ledger format includes a published test vector for independent verifiers.
