# Changelog

All notable changes to Assay are documented here. The format follows Keep a Changelog and the
project uses semantic versioning.

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
- AGPL-3.0-or-later licensing, packaging, console script, Windows/POSIX/macOS launchers and a
  three-OS CI matrix.
- Business brief, compliance mapping, threat model, launch/sales kit and contribution/security
  policies.

### Verification

- 73 unit and integration tests pass.
- AIKit Phase 4 gates pass: test, hygiene, guidelines and secret scan.
- Wheel installation, console-script execution and all three launchers were smoke-tested.
- The ledger format includes a published test vector for independent verifiers.
