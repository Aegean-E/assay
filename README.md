# Assay

[![Built with AIKit](https://img.shields.io/badge/built%20with-AIKit-6f42c1)](https://github.com/Aegean-E/AIKit)

**Tamper-evident audit evidence for AI agents.**

Assay turns agent tool calls into a hash-chained evidence ledger and a self-contained pack that
an auditor, customer or insurer can verify offline. It is local-first, zero-dependency, and
licensed **AGPL-3.0-or-later** with a commercial path for companies that embed it in proprietary
products.

Most agent tools answer "what did the agent do?" Assay answers the harder questions: was the
action allowed by the policy in force, who approved the exception, and has the record changed
since it was written?

## ⚡ Cold-Start Quick Reference

- **Runtime Prerequisites**: Python 3.10 or newer; no runtime dependencies outside the standard library.
- **Canonical Regression Shield Gate**:
  ```bash
  python -m unittest discover -s tests -t .
  ```

### 🛠️ AIKit Commands (run from the AIKit folder)

| Role | Command |
|---|---|
| Status, task and gates | `python aikit.py status assay` |
| Phase 4: every gate | `python aikit.py check assay` |
| Repair memory and map, then check | `python aikit.py fix assay` |
| Resume an interrupted task | `python aikit.py resume assay` |

## Why this exists

An agent that moves money, changes production infrastructure or exports customer data creates a
new evidence problem. Observability traces live in a vendor's retention window and are designed
for debugging. They are not a defensible record of authorisation, human oversight or integrity.

Assay produces the artefact a company keeps when the dashboard is gone:

- every action is appended to a hash chain that detects edits, deletions and reordering;
- each event can cite the policy name and digest that was active at recording time;
- a retrospective review reports denied actions, missing approvals and policy drift;
- the evidence pack embeds the records, findings, chain head and verification result;
- the verifier and the format stay open, so a third party can reproduce the result.

The intended buyers are security, compliance and AI platform leaders at companies that have moved
an agent into a regulated workflow. The business case, pricing hypotheses and go-to-market plan
live in [docs/BUSINESS.md](docs/BUSINESS.md).

## 60-second demo

From the project root:

```bash
python -m assay demo
```

The demo builds a five-event treasury-agent ledger, applies a guardrail policy, reports two
findings and writes `evidence.md` plus `evidence.json` to a temporary directory. It prints the
paths and the chain head. No network, account or configuration is needed.

Expected shape:

```text
Ledger: /tmp/assay-demo-.../ledger.jsonl (5 records, chain verified)
Policy: treasury-guardrail (8ace502b113a...)
Findings: 2
  - seq 2 payments.transfer: transfer-cap - amount 25000 exceeds 10000
  - seq 3 shell.exec: block-shell - matched rule 'block-shell'
Evidence: /tmp/assay-demo-.../evidence.md
          /tmp/assay-demo-.../evidence.json
```

Open `evidence.md` for the reviewer view; hand `evidence.json` and `ledger.jsonl` to a verifier.

## Install

Python 3.10 or newer, with no third-party runtime packages.

```bash
python -m pip install .
assay --help
```

From a checkout, `python -m assay ...` works without installing. The one-click launchers are
`run.cmd` on Windows, `run.sh` on Linux/POSIX and `run.command` on macOS.

## Use

### Record one action

```bash
python -m assay record \
  --actor agent:treasury-bot \
  --action payments.transfer \
  --target acct:vendor-17 \
  --metadata '{"amount": 4200, "approved_by": "controller@acme.example"}' \
  --policy examples/policy.json
```

The default ledger is `.assay/ledger.jsonl`. Use `--ledger PATH` to choose another file. The
record is flushed and fsynced before the command returns.

### Ingest a stream

```bash
python -m assay ingest --file examples/events.jsonl --policy examples/policy.json
cat mcp.jsonl | python -m assay ingest --format mcp --actor agent:mcp
python -m assay ingest --file openai.jsonl --format openai --actor agent:assistant
python -m assay ingest --file langgraph.jsonl --format langgraph
python -m assay ingest --file crewai.jsonl --format crewai
```

Supported formats:
- `generic`: standard JSON objects with `actor`/`agent`, `action`/`tool`, `outcome`, `metadata`.
- `mcp`: Model Context Protocol JSON-RPC `tools/call` records with session `--actor` fallback.
- `openai`: OpenAI tool calls (`function.name`, `arguments`, `tool_call_id`).
- `langgraph`: LangChain/LangGraph events (`on_tool_end`, `ToolMessage`, node actions).
- `crewai`: CrewAI task and tool telemetry (`agent`, `tool`, `tool_input`, `result`).
Every line is validated before the first event is appended.

### Verify

```bash
python -m assay verify --ledger .assay/ledger.jsonl
python -m assay verify --ledger .assay/ledger.jsonl --anchors .assay/anchors.jsonl
python -m assay verify --ledger .assay/ledger.jsonl --json
```

Exit code 0 means the chain is contiguous and every hash matches. With `--anchors`, it also confirms
every anchored head is present in the ledger, catching tail truncation and rewrites. Exit code 1 means
the evidence failed verification; the output names the bad lines. A missing ledger is a usage error (2).

### Anchor

```bash
python -m assay anchor --ledger .assay/ledger.jsonl --anchors .assay/anchors.jsonl
```

Commits the current verified ledger head to an append-only anchor journal. When signing is enabled,
pass `--key-id <ID>` alongside `--hmac-key-env` to bind key rotation identifiers to the commitment.

### Review against a policy

```bash
python -m assay review --ledger .assay/ledger.jsonl --policy pack:payments
python -m assay review --ledger .assay/ledger.jsonl --policy examples/policy.json
```

Exit code 0 means the chain is valid and no findings were raised. Exit code 1 means a verification
failure or at least one finding. Use `--json` for a machine-readable result. Built-in packs can be
referenced with `pack:<name>` or by name.

### Policy packs

```bash
python -m assay policy list
python -m assay policy show payments
```

Available curated packs:
- `payments`: transfer caps, crypto restrictions, human approval thresholds.
- `production_change`: database drops, prod shell execution, deployment approvals.
- `customer_data`: credential export blocks, bulk export caps, GDPR deletion approvals.
- `support_agent`: credential reset blocks, refund thresholds, ownership transfers.

### Write an evidence pack

```bash
python -m assay report \
  --ledger .assay/ledger.jsonl \
  --policy examples/policy.json \
  --out evidence.md
python -m assay report --ledger .assay/ledger.jsonl --policy examples/policy.json \
  --format json --out evidence.json
```

The JSON pack embeds every record and is the canonical artefact. The Markdown pack is the review
surface and shows the first 200 events with a pointer to the JSON. If the chain is broken, the
pack is still written with a `FAIL` verdict, and the command exits 1.

## Policy model

Policies are JSON, evaluated in file order with first-match semantics.

```json
{
  "schema": 1,
  "name": "treasury-guardrail",
  "default": "allow",
  "rules": [
    {"id": "block-shell", "action": "shell.*", "effect": "deny"},
    {"id": "transfer-cap", "action": "payments.*", "effect": "deny", "amount_over": 10000},
    {"id": "approve-transfers", "action": "payments.transfer", "effect": "require_approval"},
    {"id": "approve-prod-db", "action": "db.*", "effect": "require_approval",
     "metadata": {"env": "prod"}}
  ]
}
```

- `action` is an exact name or a glob; `*` matches any run of characters.
- `amount_over` and `amount_under` are exclusive thresholds. Together they define an allowed
  band: a rule with both applies outside the band.
- A rule with a threshold and a missing, non-numeric or non-finite `metadata.amount` becomes a
  deny finding. Missing amounts fail closed.
- `require_approval` is satisfied only by a non-empty `metadata.approved_by` string.
- `default` is the effect when no rule matches. Use `deny` for a strict policy.
- The policy is normalized and hashed. Events recorded with `--policy` carry its name and digest;
  reviewing old evidence under a new policy produces `policy_drift` findings instead of silently
  reinterpreting history.

## Evidence format

The ledger is JSONL. Every line has `seq`, `prev`, `event` and `hash`, plus `mac` when signing is
enabled.

```text
payload = canonical_json({"seq": seq, "prev": previous_hash, "event": event})
hash    = sha256(payload)
mac     = hmac_sha256(key, payload)
```

The genesis `prev` is 64 zero characters. Canonical JSON is sorted-key, compact, UTF-8 and rejects
NaN/Infinity. The ledger assumes one writer per file; serialize concurrent producers or give each
agent its own ledger. The full threat model, including the tail-truncation limitation, is in
[docs/SECURITY.md](docs/SECURITY.md).

### Signing

```bash
export ASSAY_HMAC_KEY='<at least 16 random bytes>'
python -m assay record --hmac-key-env ASSAY_HMAC_KEY ...
python -m assay verify --hmac-key-env ASSAY_HMAC_KEY ...
```

The key is read from the named environment variable and never from the command line. Verification
without the key still checks the chain but reports `signed: true, key_checked: false`. A hash chain
alone cannot detect a complete rewrite; protect the key and anchor the head outside the writer's
trust boundary.

## Compliance mapping

Assay supports evidence for:

- EU AI Act Article 12 record-keeping and Article 14 human-oversight evidence;
- ISO/IEC 42001 operational and incident-review evidence;
- SOC 2 monitoring, incident and change-management evidence;
- NIST AI RMF measurement and management activities.

This is evidence support, not certification and not legal advice. The field-level mapping,
recommended controls and auditor walkthrough are in [docs/COMPLIANCE.md](docs/COMPLIANCE.md).

## Commercial model

| Tier | Price hypothesis | What it adds |
|---|---:|---|
| Community | free | AGPL-3.0 core: record, ingest, verify, review, evidence packs, CLI and library |
| Team | $12k-$24k / year | Commercial license for embedding, policy packs, priority support |
| Enterprise | $60k-$150k / year | SSO, retention/WORM connectors, key custody, head anchoring, private deployment, SLA |
| Design partner | $15k / 6 months | Roadmap influence, joint evidence pack, named support |
| Readiness service | $15k-$30k | Evidence gap assessment, policy and retention design |

The Team and Enterprise rows describe the commercial offering under development; the community
core is what this repository ships today. The verifier and the evidence format are never paywalled. Commercial value comes from embedding
rights, operational connectors, policy content, assurance and support. See
[docs/BUSINESS.md](docs/BUSINESS.md) for the buyer, competition, GTM plan and 90-day strategy.

## Architecture

```text
assay/
├── adapters.py  framework transformers (MCP, OpenAI, LangGraph, CrewAI)
├── anchor.py    head commitment and journal verification
├── cli.py       command surface and exit-code contract
├── demo.py      treasury-agent scenario
├── errors.py    Error/Why/Fix failures
├── ledger.py    append, inspect, hash chain and HMAC verification
├── model.py     event contract and canonical JSON
├── packs/       built-in policy packs (payments, prod change, data, support)
├── policy.py    rule matching, first-match evaluation and findings
├── report.py    self-contained Markdown and JSON evidence packs
├── storage.py   fsynced append and atomic text writes
└── version.py   package version
```

No module imports a third-party package. The evidence path never calls a network service.

## Tests

```bash
python -m unittest discover -s tests -t .
```

The suite covers canonical serialization, event validation, chain construction, tampered records,
deleted records, malformed lines, HMAC signing, policy first-match and threshold semantics,
policy pack loading, missing amounts, evidence packs, CLI exit codes, framework adapters (OpenAI, LangGraph, CrewAI, MCP), and the demo.

## Roadmap

1. Head anchoring to an external append-only store, with a key-id and rotation format (shipped in `assay anchor` and `assay verify --anchors`).
2. Adapters for MCP servers, LangGraph, CrewAI and the OpenAI Agents SDK (shipped in `assay.adapters` and `assay ingest --format`).
3. Policy pack library for payments, production change, customer-data export and support agents (shipped in `assay.packs` and `assay policy list/show`).
4. Retention and WORM connectors for S3-compatible stores and enterprise evidence vaults.
5. Redaction workflow and PII minimization profiles.
6. A published verification specification with cross-language test vectors.

## What's Inside

```text
assay/
├── .aikit/                   <- project memory: ledger, decisions, guidelines, map
├── .github/                  <- CI matrix
├── .gitattributes
├── .gitignore
├── CHANGELOG.md
├── CONTRIBUTING.md
├── LICENSE
├── README.md
├── COMMERCIAL.md
├── SECURITY.md
├── assay/                    <- package source
├── docs/                     <- business, compliance, launch and security notes
├── examples/                 <- sample policy and event stream
├── pyproject.toml
├── run.cmd
├── run.command
├── run.sh
└── tests/
```

## Contributing and security

Development rules, the test command and contribution licensing are in
[CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md); the threat model is in [docs/SECURITY.md](docs/SECURITY.md). The
15-minute demo script, launch narrative, buyer questions and security-questionnaire answers are in
[docs/LAUNCH.md](docs/LAUNCH.md).

## License

GNU Affero General Public License v3.0 or later. See [LICENSE](LICENSE). Commercial licensing is
available for embedding in proprietary products and for enterprise operations; the open verifier
and format remain available under the AGPL.
