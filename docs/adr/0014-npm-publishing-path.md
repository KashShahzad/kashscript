# ADR-0014: Manual version bumps + `scripts/publish-to-npmjs.ts` as the active publish path

- **Status:** Accepted (recorded retroactively 2026-07-04)
- **Date:** 2026-07-04
- **Decision drivers:** OTP/token constraints of the local environment, `workspace:*` resolution at pack time, never clobbering a published version

## Context

Nine `@kashscript/*` packages publish to public npm from a Bun workspace where manifests use
`workspace:*` ranges that npm cannot consume. The publishing environment cannot answer
interactive OTP prompts, and a repo-history-driven release bot is more automation than a
small team wants on a registry with irreversible publishes. Two publish mechanisms exist in
the repo; only one is the path in use.

## Decision

**The active path is `bun scripts/publish-to-npmjs.ts [--dry-run] <dir-slug...>`:**

- Arguments are **directory** slugs under `packages/` (not scoped names); packages publish
  in the order given and the script **halts on first failure**.
- It **does not bump versions** — it publishes whatever `version` is in each
  `package.json`. Bumping is a deliberate, manual, human step, and the script **refuses to
  clobber** an already-published version.
- `workspace:*` ranges resolve to real semver ranges at pack time via `bun pm pack`;
  `--access public` is passed so first publishes work.
- Auth is a pre-existing `npm whoami` login backed by an npm **automation token** in
  `.npmrc` (the script cannot answer an OTP prompt).

**Hazards, now enforced by the script itself (2026-07-04):**

- Stale contract artifacts: if a package defines `artifacts:build` (trade-sdk's Foundry
  bytecode), the script **runs it automatically** before building — restoring the
  `prepublishOnly` step that tarball publishing bypasses (`--skip-artifacts` opts out).
- Wrong-registry publishes: the script **refuses** any package that is `private: true` or
  whose `publishConfig.registry` is not registry.npmjs.org — `@kashscript/studio`
  (local Verdaccio only) can no longer be published by accident.
- Renames still leave old names live on npm until deprecated
  (`npm deprecate "@kashscript/<old>@*" "renamed to @kashscript/<new>"`); verify live state
  with `npm view` before any publish — this one remains procedural.

**The second path is retired (2026-07-04):** `.github/workflows/release.yml` (which never
actually fired — it watched `main` while the repo works on `master`, and its deploy job
referenced the removed `services/license-server`) was replaced by `ci.yml`, which keeps
only the validation gates (typecheck + boundary check). `scripts/release.ts` was first
parked behind an explicit `KASH_RELEASE_OPT_IN=1` guard, then **removed entirely**
(2026-07-05, `CLEANUP.md` §D) once a reference check confirmed nothing invoked it — no
root `package.json` script, no workflow, no import. The guard was a transition measure;
this ADR plus git history preserve the design. `scripts/check-boundary.ts` (ADR-0007)
remains the CI gate.

## Consequences

### Positive

- Every publish is an explicit human decision with an explicit version — no surprise
  releases from commit-message wording.
- Halt-on-first-failure + refuse-to-clobber make partial publish states recoverable.
- Works within the environment's real auth constraints (no OTP interactivity).

### Negative / accepted trade-offs

- Manual version bumps can be forgotten (the script then no-ops on the clobber check —
  safe, but confusing).
- ~~The dormant conventional-commit path is drift risk~~ — retired 2026-07-04 (opt-in
  guard + `ci.yml`); reaching it now requires an explicit env var.
- No changelog automation; release notes are hand-written.

## Addendum 2026-10-28 — trusted publishing (P6, ECOSYSTEM d84(f))

The active path stays `scripts/publish-to-npmjs.ts` with manual version bumps; what changes is
who holds the credential. P6 retires the long-lived token: publishing moves to npm's trusted
publishing (OIDC) from `.github/workflows/publish.yml`, which runs the same script with
`--trusted`.

- **Per package.** `scripts/trusted-publishing.json` lists the slugs whose trusted publisher is
  configured on npmjs.com (repository, workflow `publish.yml`, environment `npm-publish`). A listed
  slug publishes only with `--trusted`, which refuses to run outside GitHub Actions with an OIDC
  token, with `NPM_TOKEN` or `NODE_AUTH_TOKEN` in the environment, or on npm older than 11.5.1.
  Without `--trusted` the script refuses a listed slug. An unlisted slug keeps the token path until
  its trusted publisher exists.
- **Triggered by hand.** `publish.yml` is `workflow_dispatch` only, from `master`, after the CI
  typecheck and boundary gates, and held by the `npm-publish` environment until the founder
  approves. The boundary check (ADR-0007) remains a gate.
- **Unchanged.** Versions are bumped by hand, clobbering is refused, and `--stage` stays a token
  feature (it cannot be combined with `--trusted`).

## Addendum 2026-11-09 — provenance, SBOM and signed releases (RW-2, P6)

Same path, same script. What RW-2 adds (`docs/publishing.md` holds the steps):

- **All twelve open packages are listed** in `scripts/trusted-publishing.json`. The token path
  refuses every one from that commit, before their trusted publishers exist on npmjs.com. A real
  run then fails at npm's OIDC exchange, which is the intended state until the founder configures
  them.
- **No credential in reach, dry runs included.** `--trusted` refuses any npm credential in the
  environment or an `.npmrc` (`scripts/publish-checks.ts`). Before RW-2 the token check ran only on
  real publishes, and only for two variable names.
- **Provenance is required, and fails closed.** A real publish passes `--provenance`, runs only
  from `refs/heads/master`, and refuses unless the job's OIDC token says the repository is
  public: npm generates provenance only from a public repository. After landing, each version must
  show `dist.attestations.provenance`. The repository is private today `[v 11-09]`, so no package
  can publish through this path until the founder makes it public or adds a public mirror. That
  was the founder's choice over publishing without provenance.
- **A dry run rehearses npmjs.com.** After the pack it makes npm's own OIDC token exchange for
  each package and discards the token. It fails with the stated reason when no trusted publisher
  answers, or when the repository is private. A dry run may run from any branch, but still inside
  the `npm-publish` environment, because the trusted publisher names it.
- **An SBOM per package.** CycloneDX 1.6, generated by `scripts/sbom.ts` from the packed manifest,
  the workspace siblings, the installed `node_modules` and `bun.lock`'s integrity values. The
  generator is ours because the stock ones need an npm tree. The format is CycloneDX's.
- **A signed release.** After a real publish, `publish.yml`'s release job writes `SHA256SUMS`,
  signs every tarball, SBOM and the sums with cosign (keyless Sigstore, the workflow's identity),
  and attaches them to a GitHub release at the published commit.

## Alternatives considered

- **semantic-release / conventional-commit automation** (`scripts/release.ts`) — built, then
  parked, then removed (2026-07-05): too much authority for an irreversible registry given team size, and its access
  default conflicts with the public tier.
- **Changesets** — reasonable future option; adds a PR-time bump workflow but another tool
  to maintain.
