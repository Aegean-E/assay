# Launch and sales kit

This is the practical material for getting a company to look, then to care, then to run a pilot.
Every asset uses the product's real behaviour; do not add claims the demo cannot reproduce.

## Launch narrative

**Observability is not evidence.**

Agent traces are built for debugging. They live in a vendor's retention window, they can be
edited by the vendor's support process, and they do not bind an action to the policy or approval
that authorised it. When a customer, auditor or insurer asks what happened, a trace screenshot is
not a defensible answer.

Assay is a local-first evidence layer: a hash-chained ledger, a policy review, and a
self-contained pack that anyone can verify offline. Source-available AL-1.1 core. Five-minute demo. No account.

## Fifteen-minute demo script

1. **Minute 0-2: state the problem.** Show an agent action log with no integrity, no policy and no
   approval. Ask: "Which policy allowed this, and how would you prove the record was not edited?"
2. **Minute 2-5: run the demo.** `python -m assay demo`. Walk through the five records, the chain
   head, the two findings and the generated Markdown pack.
3. **Minute 5-8: tamper with it.** Edit one event in a copy of `ledger.jsonl`, run `assay verify`,
   show the failure line. This is the moment buyers remember.
4. **Minute 8-11: map to their workflow.** Ask for one tool call their agent makes. Record it with
   `assay record`, attach their policy, and run `assay review`.
5. **Minute 11-14: show the operating model.** Explain retention, WORM, key custody, head
   anchoring and the difference between the free verifier and paid operations.
6. **Minute 14-15: ask for the pilot.** "Give us one agent and one audit question. We will produce
   a joint evidence pack in two weeks."

## Launch post

**Title: Observability is not evidence: an audit trail for AI agents**

AI agents now move money, change production systems and export customer data. The tooling around
them is excellent at showing what happened in a dashboard. It is much worse at producing the thing
a regulated buyer needs after an incident: a record that proves what happened, which policy was in
force, who approved the exception, and whether the record has been altered.

Today we are releasing Assay, a source-available evidence layer for agent actions. It records tool calls
in a hash-chained JSONL ledger, binds events to a policy digest, reviews the trail for denied
actions and missing approvals, and writes a self-contained evidence pack. Verification is local,
offline and reproducible. No account, no SaaS dependency, no proprietary evidence format.

Try it in one command:

```bash
python -m assay demo
```

The demo records a treasury agent, applies a guardrail policy and shows two findings: a transfer
above the cap and a shell command that should never have run. It then writes an evidence pack and
a verifier result. Edit a record and run `assay verify` to see the chain fail.

Assay is deliberately narrow. It is not a runtime firewall and not a SIEM. It is the evidence
artefact you keep when the dashboard is gone. The core is free for personal use under AL-1.1;
companies use it under the Aegean Commercial License 1.0, with retention/WORM connectors, key
custody and support planned for those that need an enterprise operating model.

If your team is deploying an agent into a regulated workflow, we would like to run a 30-minute
evidence gap review on one real action. Bring a sample; we will bring the verifier.

## Short posts

1. "Your agent trace is not an audit trail. It has no policy binding, no approval evidence and no
   independent verification. We built Assay to fix the last mile: `python -m assay demo`."
2. "A hash chain catches edits. It does not catch a truncated tail or a full rewrite. Assay's
   threat model is public because compliance buyers should know exactly what a control proves."
3. "The verifier source is public and the format is documented. If an auditor cannot reproduce the result
   without your SaaS account, it is not evidence."

## Cold email

Subject: One agent action, one evidence pack

> Hi [name],
>
> You are running an agent against [workflow]. If a customer asked which policy authorised a
> specific action, who approved it, and whether the record changed, could you answer with an
> artefact they can verify?
>
> Assay is a local-first evidence layer for agent actions: hash-chained JSONL, policy-digest
> binding, findings and a self-contained pack. The demo runs in one command and needs no account.
>
> Could we spend 30 minutes on one real action from your agent? We will produce a sample evidence
> pack and leave you the verifier.
>
> [maintainer]

## Discovery questions

- Which agent actions have a financial, production or customer-data consequence?
- Who approves an exception today, and where does that approval live?
- What retention period does your regulator, customer contract or insurer require?
- What evidence did your last security questionnaire ask for?
- Who owns the policy that should have applied, and how is it versioned?
- Is the agent allowed to write to the same storage that holds the evidence?
- What would make a pilot successful in 30 days?

## Security questionnaire answers

| Question | Answer |
|---|---|
| Deployment model | Local CLI/library or private deployment; no Assay service or subprocessor required for the community edition |
| Data residency | The operator chooses the ledger path and storage region |
| Encryption in transit | No network path in the evidence commands; deployments may add transport security for collection |
| Encryption at rest | Not provided by the community edition; use volume or bucket encryption and access controls |
| Authentication | The community edition has no user accounts; the host's file permissions and agent identity control access |
| Authorisation | Operators restrict append and read access; the enterprise roadmap adds SSO and role separation |
| Retention | Operator-controlled files; the enterprise roadmap adds WORM/object-lock connectors |
| Audit logging | The evidence ledger is the audit record; access to the storage account should be logged separately |
| Subprocessors | None in the community edition |
| Vulnerability disclosure | See `SECURITY.md`; private advisory flow, synthetic reproduction required |
| License | AL-1.1 for personal use; Aegean Commercial License 1.0 (ACL-1.0) for any company use |
| Compliance claims | Evidence support only; no certification and no legal advice |

## Objection handling

**"Do we need a license to try it?"**
No: each company group gets one 28-day non-production evaluation. Production or other company use
needs the Aegean Commercial License 1.0. The verifier source and format stay public either way.

**"A hash chain is not tamper-proof."**
Correct. It detects edits, deletions and reordering. It does not detect truncation or a full
rewrite without an external head and a protected key. We document that limitation and sell the
operational controls that close it: WORM retention, key custody and head anchoring.

**"We already have LangSmith/Langfuse."**
Keep it. Assay consumes the actions and produces the evidence artefact. Observability is for
debugging; Assay is for the audit question. The integration story is complementary.

**"We can build this ourselves."**
You can implement a hash chain in an afternoon. The hard parts are the evidence schema, policy
semantics, reviewer workflow, retention, key custody and the trust that an auditor will accept
the result. Start with the open format and buy the operations when the first real audit lands.

**"Our auditor has never heard of this."**
Give them the verification specification and the test vector in `docs/SECURITY.md`. The point is
that they do not need to trust Assay; they can recompute the result.

## Pilot success criteria

- One production-like agent workflow is recorded for two weeks.
- At least one real policy finding is reviewed and resolved.
- The buyer's security or compliance reviewer verifies a pack without help from the maintainer.
- A retention and key-custody decision is documented.
- The buyer can state the evidence question they can now answer that they could not answer before.
