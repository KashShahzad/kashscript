# Publishing the open packages — trusted publishing, provenance, SBOM, signed releases

RW-2 (2026-11-09), carrying out P6 (ECOSYSTEM d84(f)): *revoke the old npm token, publish only through npm's trusted publishing from CI.* The path stays the one ADR-0014 fixed — `scripts/publish-to-npmjs.ts`, versions bumped by hand, clobbering refused — run by `.github/workflows/publish.yml` with `--trusted`.

## 1. What the workflow does

`Actions → Publish → Run workflow` (manual only), held by the `npm-publish` environment until the founder approves.

| Step | What happens | Refuses when |
|---|---|---|
| **gates** | Typecheck, boundary check (ADR-0007), the publish-script tests, and every open package's own test suite, one package after another (`scripts/test-packages.ts`; AU-3, A10-03) — the script runs each package's tests again before it builds | any gate fails; a real run off `master` |
| **Refuse npm tokens** | Looks for any npm credential in the environment or `~/.npmrc` before anything is checked out; the script looks again, project `.npmrc` included | `NODE_AUTH_TOKEN`, `NPM_TOKEN`, an `npm_config_…_authToken`/`_auth`/`_password`, or an `.npmrc` that sets one — dry runs too |
| **Build and pack** | Cold rebuild, the `dist/` rewrite, `workspace:*` resolved from the sibling's `package.json` | a leak, a stale dependency, a missing `dist` file |
| **SBOM** | A CycloneDX 1.6 document per package (`scripts/sbom.ts`): the package and its tarball's SHA-512, the runtime closure (dependencies, optional and peer, never dev), each external's SHA-512 from `bun.lock`, the dependency graph | a required dependency is not installed |
| **Publish** (real run) | `npm publish --provenance` through OIDC: npm exchanges the job's GitHub identity for a short-lived credential and signs a SLSA provenance statement through Sigstore | the run is not on `master`; **the repository is private** (§5); a slug is not in `scripts/trusted-publishing.json` |
| **Rehearse** (dry run) | Makes npm's own OIDC token exchange for each package — the request `npm publish` makes — and discards the token unread | npmjs.com has no trusted publisher for the package; the repository is private |
| **Landing** (real run) | Waits for each version and its dist-tag on the registry, then reads `dist.attestations` | a version landed without a provenance attestation |
| **release** (real run) | `SHA256SUMS`, then `cosign sign-blob` (keyless, this workflow's identity) for every tarball, SBOM and `SHA256SUMS`; a GitHub release `npm-publish-<run number>` at the published commit, carrying the files, their `.sigstore.json` bundles and `published.json` | — |

Every run, dry or real, uploads `release/` (tarballs, SBOMs, `published.json`) as the workflow artifact `npm-release-<run id>`, kept 30 days.

`scripts/trusted-publishing.json` lists all twelve open packages, so the token path in `publish-to-npmjs.ts` refuses every one of them from this commit.

## 2. The founder's steps on npmjs.com — one trusted publisher per package

Each of the twelve exists on npm `[v 11-09, npm view]`, so each can take a trusted publisher now. For each: npmjs.com → the package → **Settings → Trusted Publisher → GitHub Actions**:

| Field | Value |
|---|---|
| Organization or user | `KashShahzad` |
| Repository | `kashscript` |
| Workflow filename | `publish.yml` |
| Environment name | `npm-publish` |

The twelve, in dependency order: `@kashscript/identity-core` · `@kashscript/lexicons` · `@kashscript/attest` · `@kashscript/identity-sdk` · `@kashscript/identity-zkp` · `@kashscript/identity-server` · `@kashscript/muffler` · `@kashscript/terms` · `@kashscript/predicate` · `@kashscript/wallet` · `@kashscript/whiffin` · `@kashscript/kash`.

## 3. The canary dry run — `terms`

A dry run publishes nothing. It builds and packs `terms`, writes its SBOM, makes npm's OIDC exchange for it, and checks the repository's visibility.

1. Push the work to a branch, e.g. `git push origin master:rw-2-canary` (or run from `master` and skip step 2).
2. GitHub → the repository → **Settings → Environments → `npm-publish` → Deployment branches and tags**: add `rw-2-canary`. The environment otherwise holds runs to `master`, and the dry run must run in it, because the trusted publisher names it. Remove the rule afterwards.
3. **Actions → Publish → Run workflow**: branch `rw-2-canary`, `packages` = `terms`, `dry_run` = ticked. Or: `gh workflow run publish.yml --ref rw-2-canary -f packages=terms -f dry_run=true`.
4. Approve the `npm-publish` environment. Read the *Publish* step's log.

**The outcomes, and what each says.** Exactly one of these ends the run:

| State | The log says | Run |
|---|---|---|
| No trusted publisher for `terms` yet | `✗ HALT at terms: npmjs.com is not yet configured for @kashscript/terms: the OIDC exchange answered HTTP <status>: <npm's message>` | fails |
| Trusted publisher in place, repository private (the archive, before AU-11) | `✓ npmjs.com: the trusted publisher answers for @kashscript/terms`, then `✗ HALT at terms: provenance impossible: KashShahzad/kashscript is private — npm generates provenance only from a public source repository …` | fails |
| Trusted publisher in place, repository public (AU-11 onward) | both `✓` lines, `provenance: the repository is public; npm will generate it at publish`, `validated: 1 / 1` | passes |

Either failure is the done condition RW-2 named: the run fails for a stated reason. A dry run **cannot produce provenance itself** — npm creates it only during a real publish (npm 11, `lib/commands/publish.js`) — so the third row is the most a dry run can show.

## 4. Verification

After a real publish:

```sh
npm view @kashscript/<pkg>@<version> --json | jq .dist.attestations
# → { "url": "https://registry.npmjs.org/-/npm/v1/attestations/@kashscript%2f<pkg>@<version>",
#     "provenance": { "predicateType": "https://slsa.dev/provenance/v1" } }

npm audit signatures        # in any project that installs it: registry signatures and provenance
```

The workflow reads the same field after landing, and fails the run when the attestation is missing.

From the GitHub release's files:

```sh
sha256sum -c SHA256SUMS
cosign verify-blob --bundle <file>.sigstore.json \
  --certificate-identity https://github.com/KashShahzad/kashscript/.github/workflows/publish.yml@refs/heads/master \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com <file>
```

The SBOM (`<pkg>-<version>.cdx.json`) validates against CycloneDX 1.6. `kash` and `terms` were checked with `cyclonedx/cyclonedx-cli:0.27.2 validate --input-version v1_6 --fail-on-errors` `[v 11-09]`.

## 5. Provenance needs a public repository — the public repository (AU-11)

npm creates provenance only from a public source repository:

- npm 11 turns it on only when the OIDC token's `repository_visibility` is `public` (`lib/utils/oidc.js`);
- npm's documentation on trusted publishing (docs.npmjs.com/trusted-publishers, read 2026-11-09) says: *"Provenance generation is not supported for private repositories, even when publishing public packages."*

RW-2 **fails closed** (the founder's choice, 2026-11-09): a real publish refuses while the repository is private, so nothing ships without provenance.

**The route taken (d97(n), AU-11, ADR-0028):** the twelve packages publish from a public repository, `KashShahzad/kashscript`, that holds only the open protocol and starts from a clean history. The repository they were developed in until then is renamed and kept private as the archive: its history holds closed code that left on 2026-11-02 and the retired trade packages. The tree is built by `scripts/export-public-tree.ts` and checked by `scripts/check-public-tree.ts`. The founder's steps — create, push, register the trusted publishers, publish with provenance, move `latest` — are a checklist kept with the archive (`docs/public-repository.md` there).

Provenance names the source repository, and npm refuses a package whose `repository.url` names another (E422). Every open package declares `{ "type": "git", "url": "git+https://github.com/KashShahzad/kashscript.git", "directory": "packages/<slug>" }`. `scripts/check-boundary.ts` enforces it, and `--trusted` refuses a mismatch against `GITHUB_REPOSITORY` before anything is built.

The one release published by hand, without provenance, is AU-3's (identity-core 0.4.0-alpha.1 and alpha.2, attest 0.2.0-alpha.9 and alpha.10, predicate 0.3.0-alpha.1 and alpha.2; d97(n)). Every later version carries provenance.

## 6. Then: revoke the tokens

When each package has its trusted publisher (§2) and a dry run of all twelve passes the exchange:

1. npmjs.com → **Access Tokens**: revoke all eight granular tokens (each made for one job: hudhud, wallet, predicate …).
2. Delete the `_authToken` line from the local, gitignored `Kashscript 2.0/.npmrc`, and from `~/.npmrc` if it has one. The workflow refuses a run when either is present on a runner. Locally they only block a `--trusted` rehearsal, which needs CI anyway.
3. On each package: **Settings → Publishing access → Require two-factor authentication and disallow tokens**.

Revoking the tokens does not wait for §5; a publish waits for the public repository. npm removes direct publishing from tokens that bypass two-factor authentication around January 2027 in any case.

## What this does not do

- **The session publishes nothing.** Pushing, dispatching and approving the workflow are the founder's.
- **The SBOM describes the runtime closure as installed in this workspace** (`bun install --frozen-lockfile`). A consumer's install can resolve the same ranges to other versions, and their own lockfile decides that. The generator is ours, because the stock generators need an npm tree, and a sibling published in the same batch is not on the registry yet. The format is CycloneDX's.
- **Keyless signing logs publicly.** Each cosign signature is entered in Sigstore's public transparency log under this workflow's identity. The release job runs only after a real publish, which already requires a public repository.
