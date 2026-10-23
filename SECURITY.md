# Security policy

Assay records and verifies security-relevant evidence. Please disclose suspected vulnerabilities
privately so users can rotate keys and preserve affected ledgers before details become public.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |
| older | no |

## Reporting a vulnerability

- Do not open a public issue containing live ledger data, secrets, customer identifiers or an
  exploitable reproduction against a production deployment.
- Use the private security advisory flow of the repository that hosts this project.
- Include the version, a minimal reproduction built from synthetic events, the expected result and
  the observed result.
- If a signing key may have been exposed, rotate it first and state that rotation in the report.

We aim to acknowledge a report within two business days and to agree a disclosure timeline with
the reporter. Good-faith research on your own deployment is welcome; do not test against systems
you do not own or have permission to assess.

## Scope

In scope:

- hash-chain construction and verification;
- HMAC signing and key handling;
- canonical JSON and event validation;
- policy matching, first-match order and fail-closed amount checks;
- evidence-pack integrity and the CLI exit-code contract;
- path handling, atomic writes and denial of service through malformed input.

Out of scope:

- the truthfulness of a producer that records false or incomplete events;
- compromise of the host, the Python interpreter or the storage account;
- social engineering and physical access;
- third-party services that a deployment chooses to connect.

The full threat model, including the tail-truncation limitation and key-custody guidance, is in
[docs/SECURITY.md](docs/SECURITY.md).
