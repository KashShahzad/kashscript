# KashScript open protocol — working notes for coding agents

Bun monorepo; the workspaces are `packages/*`, the twelve open `@kashscript/*` packages. Read
[README.md](README.md) first.

- **What may enter:** only what checking a record or the person's wallet needs (ecosystem decision 87).
  `scripts/check-public-tree.ts` refuses closed or private paths. Never add an app, a site, a server
  we operate, or code that ranks, scores or searches for people, or that moves money.
- **Verify before claiming done:** `bun scripts/test-packages.ts --only <slug>` (the tests' typecheck,
  then every test), `bun run typecheck`, `bun scripts/check-boundary.ts`,
  `bun scripts/check-public-tree.ts .`. The CLI tests spawn node and a browser; under load, rerun
  with `bun test --timeout 30000`.
- **Versions and publishing:** the publish script does not bump versions. Publishing happens only in
  `.github/workflows/publish.yml`, run by the founder; a session never publishes, pushes or moves a
  dist-tag ([docs/publishing.md](docs/publishing.md)).
- **Commits:** put the prompt's label first, and commit only when asked.
- **Never** `www.` in protocol identifiers (DID `@context`, lexicon and spec `$id`s, WebAuthn `rpId`):
  they stay on the bare `kashscript.com`.
