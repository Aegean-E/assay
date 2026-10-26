# Decisions

Why this project is built the way it is, oldest first. One entry per decision that changes a
contract, a dependency, a data format or the architecture; IDs are consecutive and never reused.

### ADR-001: AGPL-3.0-or-later core with a commercial licensing path
- **Date**: 2026-10-23
- **Status**: Accepted
- **Context**: Companies will self-host evidence software and may embed it in proprietary
  products. The project must stay open enough to be trusted by auditors and funded by the
  companies that capture the most value.
- **Decision**: License the whole project under AGPL-3.0-or-later. Sell commercial licenses for
  embedding, enterprise support, policy packs, retention connectors and signed evidence
  operations. Never paywall the verifier or the evidence format.
- **Consequences**: Closed-source SaaS use requires a commercial license. The open core remains
  auditable and offline-verifiable, which is the trust argument the product depends on.

### ADR-002: JSONL hash chain with optional HMAC signing
- **Date**: 2026-10-23
- **Status**: Accepted
- **Context**: Evidence must be portable, append-only and verifiable with the standard library
  only. A database would hide the integrity rules behind a vendor-specific engine.
- **Decision**: Store one canonical-JSON record per line. Each record contains `seq`, `prev`,
  `event` and `hash`, where `hash = SHA-256(canonical({"seq","prev","event"}))`. An optional
  `mac = HMAC-SHA256(key, same payload)` lets a key holder detect a full-chain rewrite.
- **Consequences**: Humans and auditors can reimplement verification in any language. A hash
  chain alone cannot detect truncation or a complete rewrite; deployments should anchor the head
  and protect the HMAC key. See `docs/SECURITY.md`.

### ADR-003: First-match policies bound to a policy digest
- **Date**: 2026-10-23
- **Status**: Accepted
- **Context**: A review finding is only defensible if the reviewer knows which policy was in
  force when the action happened. Rule engines that silently combine rules are hard to explain.
- **Decision**: Evaluate rules in file order and stop at the first match. Support exact action
  globs, exact metadata matches, and `amount_over` / `amount_under` thresholds. Any amount rule
  that cannot see a finite numeric `amount` becomes a deny finding. Hash the normalized policy
  and store its digest on events recorded with `--policy`.
- **Consequences**: Policy order is part of the contract and must be reviewed. Missing amounts
  fail closed. A later policy change is visible as `policy_drift` rather than silently
  reinterpreted history.

### ADR-004: Self-contained evidence packs and a strict exit-code contract
- **Date**: 2026-10-23
- **Status**: Accepted
- **Context**: An evidence pack is often copied to a buyer, auditor or insurer who cannot access
  the original repository. Findings without records are not evidence.
- **Decision**: The JSON pack embeds every ledger envelope, the verification result, policy
  metadata, findings and the chain head. Markdown is a human review surface, capped at 200 event
  rows, with a pointer to the JSON for the complete set. Commands return 0 for success, 1 for a
  failed verification or policy finding, and 2 for usage, configuration or input errors.
- **Consequences**: Packs can be large and may contain sensitive metadata. Producers must
  minimize PII. `report` still writes a FAIL pack when the chain is broken, then exits 1.

### ADR-005: Zero runtime dependencies and Python 3.10+
- **Date**: 2026-10-23
- **Status**: Accepted
- **Context**: Security and compliance teams must be able to vendor, inspect and run the verifier
  in locked-down environments. A dependency tree expands the supply-chain review.
- **Decision**: Use only the Python standard library at runtime. Require Python 3.10 or newer.
  Keep packaging limited to `setuptools` at build time. Do not call external services from the
  recording, verification or reporting path.
- **Consequences**: Some conveniences (Ed25519, SQLite indexing, cloud storage adapters) move to
  optional enterprise components or later versions. The core remains auditable in one sitting.

### ADR-006: Head anchoring journal with key identification and rotation format
- **Date**: 2026-10-24
- **Status**: Accepted
- **Context**: Hash chains alone cannot detect tail truncation or a full rewrite. Operators need to
  anchor the head seq and hash to an independent append-only journal, with a key ID for HMAC
  rotation without exposing secrets.
- **Decision**: Introduce `AnchorJournal` and the `assay anchor` command. Store canonical JSON records
  with `schema`, `ledger`, `seq`, `head`, `created_at`, `key_id`, `prev`, and `hash`. Require
  `--key-id` whenever `--hmac-key-env` is used to bind anchors to key rotation identifiers.
  `assay verify --anchors FILE` validates that every anchored head matches the ledger and refuses
  truncated tails or rewritten chains.
- **Consequences**: Truncation and rewrites are detectable offline with the standard library. Anchor
  files are append-only and independently verifiable. Key rotations do not break verification history.

### ADR-007: Zero-dependency agent framework adapters
- **Date**: 2026-10-24
- **Status**: Accepted
- **Context**: Autonomous agents built on MCP, OpenAI Agents SDK, LangGraph, or CrewAI emit
  heterogeneous event structures. Requiring developer teams to install heavy SDK dependencies
  inside Assay or write manual transformation glue slows adoption and introduces supply-chain risk.
- **Decision**: Ship pure standard-library adapters in `assay.adapters` that transform JSON-RPC
  and dictionary telemetry from MCP, OpenAI, LangGraph, and CrewAI into canonical `Event` records.
  Support stream ingestion via `assay ingest --format <name>` with session actor fallbacks.
  Duck-type dictionary payloads without requiring runtime SDK packages.
- **Consequences**: Assay integrates out-of-the-box with the top 4 agent ecosystems without
  violating ADR-005 (zero runtime dependencies). Developers can pipe telemetry directly to
  the CLI or call `adapt_event` in code.

### ADR-008: Curated policy pack library and pack resolution
- **Date**: 2026-10-24
- **Status**: Accepted
- **Context**: Compliance and risk teams evaluating agent systems need ready-to-use guardrail
  policies for common regulated workflows (payments, infrastructure changes, customer PII data,
  and support operations). Writing JSON policy rules from scratch creates friction and leads to
  inconsistent rule definitions across organizations.
- **Decision**: Ship curated, version-controlled policy packs inside the package (`assay/packs/`)
  covering `payments`, `production_change`, `customer_data`, and `support_agent`. Enable direct
  resolution via `pack:<name>` or bare name across all policy-aware CLI commands and Python APIs.
  Introduce `assay policy list` and `assay policy show` for offline pack inspection.
- **Consequences**: Evaluators can evaluate live agent traces against enterprise guardrails in
  seconds. Packs are self-contained, canonical JSON documents with deterministic SHA-256 digests.
## Licensing migration (v0.1.0-agpl)

- New versions use Aegean License 1.1 (AL-1.1); versions at or before `v0.1.0-agpl` remain AGPL-3.0.
- Rights holder: AegeanWorks; internal AI commit identity `assistant@local`.
- Counsel review of the 1.1 texts remains pending.

