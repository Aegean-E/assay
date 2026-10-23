# Contributing

Assay is an evidence tool. A change that makes verification ambiguous, hides a failure or weakens
a test is a product regression even when the feature works.

## Development setup

Python 3.10 or newer; no runtime dependencies.

```bash
git clone <repository>
cd assay
python -m unittest discover -s tests -t .
python -m assay demo
```

The demo writes a temporary ledger and evidence pack. There is no service to start and no
database to migrate.

## Change rules

- Keep the runtime on the Python standard library. A new dependency needs an ADR and a clear
  supply-chain argument.
- Add a failing-first regression test for every behavior change. Do not weaken or delete an
  existing test to make a change pass.
- Preserve the `Error:` / `Why:` / `Fix:` triad on user-facing failures.
- Preserve exit codes: 0 for success, 1 for failed verification or policy findings, 2 for usage,
  configuration or input errors.
- Changes to the event schema, hash formula, policy digest, evidence-pack schema or exit-code
  contract require an ADR in `.aikit/decisions.md`.
- Keep policy evaluation deterministic: file order, first match, no hidden precedence.
- Do not add telemetry, network calls or background processes to the evidence path.

## Style

- Use `pathlib.Path` and explicit encodings.
- Bound subprocess calls; prefer no subprocess at all.
- Use atomic writes for generated files and fsynced appends for evidence.
- Keep modules named after what they hold, not `utils`, `helpers` or `common`.
- Document the threat-model consequence of a security-sensitive change in `docs/SECURITY.md`.

## Contribution licensing

Contributions are accepted under AGPL-3.0-or-later, the license of this project. Because Assay is
also offered under a commercial license, the maintainer may require a contributor license
agreement before merging a substantial contribution. Open an issue before starting a large change
so the licensing and design questions are settled first.

## Commit messages

Use conventional commits, for example:

```text
feat(ledger): anchor the head to an external store
fix(policy): deny rules with an unverifiable amount
docs(security): document key rotation at ledger boundaries
```

Keep the subject imperative and under 72 characters. Explain the why in the body when the change
affects evidence semantics.
