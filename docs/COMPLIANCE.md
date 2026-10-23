# Compliance evidence mapping

> Assay produces evidence. It is not a certification body and this document is not legal advice.
> Validate the mapping with your counsel, auditor and the authority that applies to your system.

## What the pack can support

| Obligation or framework | Evidence in an Assay pack | What it does not prove |
|---|---|---|
| EU AI Act Article 12 (record-keeping) | Per-action records with actor, action, target, outcome, timestamp, policy name/digest, contiguous sequence and a verifiable chain head | That the producer logged every event; that the clock was trusted |
| EU AI Act Article 14 (human oversight) | `require_approval` findings and `metadata.approved_by` on events; missing approvals become findings | That the named approver is who they claim to be; that the approval was informed |
| EU AI Act Annex IV (technical documentation) | Evidence pack as a supporting artefact for the logging and human-oversight sections | That the pack is a complete Annex IV submission |
| ISO/IEC 42001 (AI management system) | Operational evidence for defined controls, incident review, monitoring and corrective action | Certification or conformity with the standard |
| SOC 2 CC7.2 / CC7.3 (monitoring and incidents) | Action-level records, findings and chain verification for an incident review | That the service organisation meets every trust-services criterion |
| SOC 2 CC8.1 (change management) | Evidence of production-change actions, targets, approvals and policy findings | That the change was authorised by the change board |
| NIST AI RMF (MEASURE / MANAGE) | Measurable policy findings and a retained record for risk response | A complete RMF profile or assessment |

## Evidence fields and why they matter

| Field | Purpose |
|---|---|
| `schema` | Lets a verifier reject a format it cannot interpret |
| `id` | Stable event identity, independent of ledger position |
| `ts` | Time of the action, normalized to UTC; the producer supplies it |
| `actor` | The agent or principal that acted |
| `action` | Tool or operation name, used by policy rules |
| `outcome` | Success, error, denied or pending |
| `target` | Resource addressed by the action |
| `metadata` | Amounts, approvals, environment and other reviewable facts |
| `policy.name` / `policy.digest` | The policy that was in force when the event was recorded |
| `seq` / `prev` / `hash` | Position, predecessor and SHA-256 commitment |
| `mac` | Optional HMAC-SHA256 signature for deployments that hold a verification key |

The policy digest is computed over a normalized policy document. Two files with different
formatting but the same rules produce the same digest. A later policy change shows up as a
`policy_drift` finding when the old evidence is reviewed against the new policy.

## Recommended control set

1. **Identity**: give every agent a distinct actor identifier. Do not share one service account
   across agents, environments or tenants.
2. **Policy**: keep policy files in version control. Record with `--policy` so each event commits
   to the policy digest. Review policy order as part of change control.
3. **Approval**: require `metadata.approved_by` for actions that need human oversight. Keep the
   approval identity in the same system of record as the action.
4. **Retention**: store ledgers in append-only or WORM storage for the retention period required
   by your regime. Keep a copy outside the agent's write scope.
5. **Key custody**: if using HMAC signing, keep the key in a secrets manager or HSM, restrict it
   to the recorder and verifier roles, and rotate with a documented key-id plan.
6. **Anchoring**: publish the chain head to an independent store on a schedule. A hash chain
   cannot detect truncation of its tail without an external commitment.
7. **Access**: separate the agent that writes events from the human who reviews them. Log access
   to the evidence store itself.
8. **Verification**: run `assay verify` on a schedule and after every restore. Treat a failure as
   a security incident, not a reporting nuisance.
9. **Minimization**: keep PII out of `metadata` unless it is necessary for the audit question.
   Redact upstream; the ledger is not an encrypted store.

## Auditor walkthrough

1. Receive `evidence.json` and the ledger file.
2. Run `assay verify --ledger <file>` and compare the reported head with the pack's
   `ledger.head`.
3. Recompute one record from `seq`, `prev` and `event` using the specification in
   `docs/SECURITY.md`.
4. Compare the pack's policy digest with the policy file held by the reviewer.
5. Review findings by `seq`; confirm the approval identity and the policy exception process.
6. Check the external head anchor for the retention window.

## Known gaps

- Assay does not observe the agent; it records what the producer sends.
- Assay does not enforce policy at runtime. It reviews the recorded trail. Pair it with a gateway
  or runtime guardrail if pre-execution blocking is required.
- Assay does not provide trusted time. Use NTP and, where required, a timestamp authority.
- Assay does not encrypt the ledger at rest. Use volume or bucket encryption and access controls.
- The community edition does not integrate with an identity provider or a WORM store. Those are
  enterprise operations, not verification features.
