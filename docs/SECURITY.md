# Security and threat model

## Assets

- The integrity of the evidence ledger and every evidence pack.
- The HMAC key, when signing is enabled.
- The confidentiality of event metadata, which may contain amounts, identifiers or customer data.
- The availability of the verifier in a locked-down environment.

## What the hash chain proves

For every record `n`, Assay stores:

```text
payload(n) = canonical_json({"seq": n, "prev": hash(n-1), "event": event(n)})
hash(n)    = sha256(payload(n))
```

The genesis `prev` is 64 zero characters. Verification walks the file, checks that `seq` is
contiguous, `prev` equals the previous hash, and `hash` equals the recomputed value. Canonical
JSON means sorted keys, no insignificant whitespace, UTF-8, and no NaN or Infinity.

An optional HMAC is computed over the same payload:

```text
mac(n) = hmac_sha256(key, payload(n))
```

### Published test vector

The following event at `seq = 0`, with genesis `prev = 0000...0000`, must produce these values.
The HMAC key is the 32 ASCII bytes `0123456789abcdef0123456789abcdef`:

```json
{
  "schema": 1,
  "id": "0123456789abcdef0123456789abcdef",
  "ts": "2026-10-23T09:00:00Z",
  "actor": "agent:treasury-bot",
  "action": "payments.transfer",
  "outcome": "success",
  "target": "acct:vendor-17",
  "metadata": {"amount": 4200, "approved_by": "controller@acme.example"}
}
```

```text
hash = 05e5bac80adac169419c1d1629545eace7af484da5c80c69be5e2fd42d1b8bcf
mac  = 83005ac693ef1c086b7efa336be63fbfc11fe8a16ae50948b4714d89f8ce0272
```

The regression suite asserts both values. A third-party verifier can use this vector to check its
canonical JSON and HMAC implementation before trusting a production pack.

## Threats and outcomes

| Threat | Without HMAC | With HMAC and protected key |
|---|---|---|
| Accidental edit to one event | Detected by hash mismatch | Detected |
| Deliberate edit to one event | Detected by hash mismatch | Detected |
| Deletion of a middle record | Detected by seq/prev mismatch | Detected |
| Reordering records | Detected by seq/prev mismatch | Detected |
| Truncation of the tail | **Not detected** by the chain alone | **Not detected** by the chain alone |
| Rewrite of the entire chain | **Not detected** by the hash chain alone | Detected by HMAC mismatch |
| Key compromise | n/a | Attacker can forge; rotate and re-anchor |
| Producer omits an action | Not detectable | Not detectable |
| Producer lies before recording | Not detectable | Not detectable |

**Truncation is the important limitation.** A shorter chain is still a valid chain. Publish the
head to an independent store on a schedule, or store the ledger in WORM media whose retention
policy prevents deletion, so a reviewer can compare the pack's head with an external commitment.
Head anchoring is the first enterprise roadmap item.

## Key handling

- Pass a key only through an environment variable named by `--hmac-key-env`. Never put a key in
  `argv`, a policy file or the ledger.
- Use at least 16 random bytes. A 32-byte random key encoded as hex or base64 is a reasonable
  starting point.
- Keep the key outside the agent's write scope. The agent should be able to append events; it
  should not be able to read the verification key.
- Record the key identifier and rotation date in your operations runbook. The current format has
  no key id, so plan rotations at ledger boundaries in this version.
- Verification without the key still validates the chain. It reports `signed: true` and
  `key_checked: false`; do not present that as signature verification.

## Metadata and PII

Events are not encrypted. `metadata` is stored verbatim in JSON and copied into every evidence
pack. Treat the ledger as a sensitive record:

- Record identifiers, amounts, decisions and targets needed for the audit question.
- Avoid free-text customer content, credentials, access tokens or full request bodies.
- Redact upstream; do not rely on the ledger to forget data later.
- Apply volume or bucket encryption, access logging and least-privilege permissions.
- Set a retention period and delete whole ledgers under a documented policy.

## Operational guidance

1. Use one writer per ledger file. The append operation is fsynced but does not coordinate
   concurrent producers; give each agent its own ledger or serialize appends through a queue.
2. Store ledgers on append-only media or in a bucket with object-lock retention.
3. Restrict write access to the recorder identity. Restrict read access to reviewers and auditors.
4. Run `assay verify` after every restore, deployment and retention change.
5. Keep a copy of the head outside the recorder's trust boundary.
6. Back up the ledger and the policy files together; a pack references a policy digest.
7. Treat a verification failure as a security incident with a preserved copy of the file.
8. Test the recovery path with a deliberately tampered copy in a non-production environment.

## Reporting a vulnerability

Do not include live ledger data or secrets in a public report. Provide the affected version, a
minimal reproduction with synthetic events, and the expected versus observed verification result.
Rotate any key that may have been exposed before investigating further.
