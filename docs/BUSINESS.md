# Assay business brief

## Thesis

AI observability answers "what did the agent do?" It does not answer the questions a regulated
buyer asks after an incident:

- Was the action allowed by the policy in force at that moment?
- Who approved the exception, and can we prove the approval was not added later?
- Has the record been altered since the agent acted?
- Can we hand a customer, auditor or insurer something they can verify without our SaaS account?

Assay is the evidence layer for those questions. It records agent actions in a hash-chained,
locally verifiable ledger, binds each event to a policy digest, and produces a self-contained
evidence pack. The product is deliberately narrow: it is not a dashboard, not a runtime
firewall, and not a SIEM. It is the artefact a company keeps when the dashboard is gone.

## Buyer and pain

**Primary buyer**: Head of AI, VP Engineering, CISO or compliance lead at a company that has
moved an agent from a demo into a workflow that touches money, production systems or customer
data.

**Company profile**: 200-5,000 employees; regulated or enterprise-sold (fintech, insurance,
healthcare, B2B SaaS with SOC 2 obligations); using LangGraph, CrewAI, the OpenAI Agents SDK, a
custom orchestrator or MCP tools; already paying for observability and still unable to answer an
auditor's evidence request.

**Trigger events**:

- A customer security questionnaire asks for agent action logs and approval evidence.
- An internal audit finds that an agent exception was approved in chat, with no durable record.
- Legal asks whether an agent's action was compliant with the policy that was active last quarter.
- A board or insurer asks for evidence of human oversight before expanding agent autonomy.

**Budget owner**: security/compliance, not the innovation lab. Assay is positioned as evidence
infrastructure, so it competes with governance platforms and audit preparation time, not with a
$20/month tracing tool.

## Product and packaging

| Tier | Price hypothesis | What the buyer gets |
|---|---:|---|
| Community | free | AGPL-3.0 core: record, ingest, verify, policy review, evidence packs, CLI and library |
| Team | $12k-$24k / year | Commercial license for embedding, policy pack library, priority issues, upgrade guidance |
| Enterprise (roadmap) | $60k-$150k / year | SSO, retention and WORM connectors, key-custody integration, signed head anchoring, private deployment, SLA |
| Design partner | $15k / 6 months | Roadmap influence, two compliance use cases, joint reference pack, named support |
| Readiness service | $15k-$30k | Two-week evidence gap assessment, policy and retention design, auditor-ready sample pack |

The commercial license is for companies that cannot accept AGPL obligations because they embed
Assay in a closed product or distribute it with a proprietary appliance. The verifier and the
open format stay free. That is both the trust story and the distribution strategy.

## Why AGPL-3.0

- Compliance buyers can inspect the integrity rules instead of trusting a vendor's badge.
- A cloud provider cannot take the core, close it and sell it back without contributing or
  buying a commercial license.
- Companies that only self-host internally can use the community edition at no cost, which keeps
  adoption friction low.
- The paid surface is operational: retention, identity, key custody, policy content, support and
  assurance. None of it requires hiding the verification algorithm.

## Go-to-market

The reusable launch narrative, demo script, cold email, discovery questions and security
questionnaire answers are in [LAUNCH.md](LAUNCH.md).

1. **Proof over pitch.** Publish the 60-second demo, a sample evidence pack and a reproducible
   tamper test. Security buyers forward artefacts, not landing pages.
2. **Integrations as distribution.** Ship adapters for MCP, LangGraph, CrewAI and the OpenAI
   Agents SDK. Each adapter gets a short "record evidence in five lines" guide.
3. **Compliance content.** Publish a practical guide to AI agent record-keeping that maps
   evidence fields to EU AI Act Article 12/14, ISO/IEC 42001 and SOC 2. Give away the mapping;
   sell the operating model, retention and support.
4. **Design partners.** Recruit five companies with a live agent in a regulated workflow. Run a
   joint evidence gap assessment. Convert two into paid pilots with a defined success metric.
5. **Partner channel.** Boutique AI-governance consultancies need a technical evidence layer.
   Offer a referral margin and a reusable assessment kit.
6. **Open-source credibility.** Keep the issue tracker public, publish a verification
   specification and a test vector, and accept third-party auditors' review of the format.

## Competition and differentiation

| Category | Examples | Gap Assay exploits |
|---|---|---|
| Agent observability | LangSmith, Langfuse, AgentOps | Traces are operational data, not tamper-evident evidence; retention and ownership are vendor-shaped |
| AI governance platforms | Credo AI, Holistic AI, Trustible | Strong process and inventory, weak low-level action evidence; often SaaS-only |
| Cloud audit logs | Cloud provider audit trails | Record cloud API calls, not agent intent, policy or human approval |
| Home-grown JSON logs | internal scripts | No canonical format, no chain, no independent verifier, no policy binding |

The defensible combination is **local-first + offline verification + policy digest binding + a
format an auditor can reimplement**. The hash function is not the moat; the evidence schema,
policy packs, integrations and trust built around them are.

## Success metrics

- Time from `pip install` to a verified evidence pack: under 5 minutes.
- Demo-to-record conversion: percentage of evaluators who record their own event in week one.
- Weekly active organisations and events recorded.
- Evidence packs generated per organisation per month.
- Findings per 100 events, and the share of findings resolved by policy or process change.
- Design partners signed, paid conversions, net revenue retention.
- Verification failures in production (target: zero unexplained).

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Cloud observability vendors bundle "audit" features | Win on local-first ownership, offline verification and AGPL trust; integrate rather than compete on dashboards |
| Buyers treat a hash chain as a silver bullet | Publish the threat model, truncation limitation, key custody guidance and anchoring roadmap |
| Legal review rejects compliance claims | Never claim certification; use "supports evidence for" and partner with counsel/auditors |
| PII accumulates in evidence metadata | Provide minimization guidance and a redaction workflow; keep encryption-at-rest in the enterprise tier |
| Key management is too hard for mid-market | Default to unsigned chains with hash verification; offer managed key custody and head anchoring as paid operations |
| Open-source clones | Build the policy pack library, integrations and reference customers; the format is a commons, the operations are the product |

## 90-day plan

1. Weeks 1-2: publish the demo, evidence pack and threat model; recruit three design partners.
2. Weeks 3-5: add MCP and framework adapters; publish the verification specification and test
   vectors; run two evidence gap assessments.
3. Weeks 6-8: add head anchoring to an external store and a retention connector prototype; ship
   the first policy pack (payments and production-change agents).
4. Weeks 9-12: publish two anonymized case studies, test Team pricing, and convert two design
   partners to paid pilots.

## Ask

Introductions to security, compliance or AI platform leaders at companies with a live agent in a
regulated workflow. The best first conversation is a 30-minute evidence gap review using the
buyer's own agent action sample.
