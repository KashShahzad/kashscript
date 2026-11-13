# ADR-0028: The open protocol gets its own public repository, from a clean history

- **Status:** Accepted (AU-11, prepared 2026-11-13). The repository is created, pushed and given its trusted publishers by the founder.
- **Date:** 2026-11-13
- **Decision drivers:** ECOSYSTEM d87 (open where checking needs it; apps and operations closed), d97(n) (the kernel's publish path: open the repository from a clean history), P6 / d84(f) (trusted publishing only), RW-2 (no publish without provenance, fail closed), AUDIT-2026-11-11 A10-04 (no publish path while the repository is private)

## Context

RW-2 lets a package publish only through npm's trusted publishing, with provenance, and refuses otherwise. npm generates provenance only from a public source repository. The repository the kernel was built in, `KashShahzad/kashscript`, is private, so after RW-2 no fix to attest, predicate or wallet could reach npm the trusted way (A10-04). AU-3's fix went out once by hand without provenance, under d97(n).

That repository could not simply be made public:

- **Its history holds closed code.** hudhud, neuron and the Policy to door kit lived here until they left for Oreoasis on 2026-11-02 (KS-P1, ADR-0024). `trade-core` carried `escrow` and `trustScore`.
- **Its tree holds more than the protocol.** It also holds kashscript.com, Kashverse, the labs, the internal catalogue and brand packages, and the services. d87 keeps the apps and operations closed, and the root licence calls them proprietary.

## Decision

1. **A new public repository holds the open protocol only.** It holds the twelve packages that d87's test opens, the specifications of open packages and record formats, the decision records they cite, the open rulebooks, and the scripts and workflows that test and publish them.
2. **It starts from a clean history.** `scripts/export-public-tree.ts` copies the tracked files that `scripts/public-tree/manifest.json` admits (an allowlist), then lays `scripts/public-tree/overlay/` over them. The overlay holds the files that differ: the README, LICENSE, CONTRIBUTING, CLAUDE.md, the root `package.json` with `packages/*` as the only workspaces, CI without the site's gates, the gitleaks configuration and the security baseline. The founder's first commit there is the whole tree.
3. **It takes the name `KashShahzad/kashscript`.** The private repository is renamed (for example to `kashscript-archive`) and kept private as the archive. For now it is also the home of the sites, which deploy from it as before. The trusted publishers, the cosign identity in `docs/publishing.md` and every package's `repository.url` name the public repository.
4. **Nothing closed can enter it later.** `scripts/check-public-tree.ts` runs on every push there. It refuses a closed or private path (apps, services, the internal packages, hudhud, neuron, trade, the Policy to door kit, credentials files), a broken relative link, and a `trusted-publishing.json` that does not list exactly the open packages. It also checks that each packed tarball holds only what its `files` admits.
5. **Every open package declares the repository** (`git+https://github.com/KashShahzad/kashscript.git`, with its own `directory`). npm refuses provenance whose source repository does not match (E422). `scripts/check-boundary.ts` enforces the field, and `--trusted` refuses a mismatch against `GITHUB_REPOSITORY` before building.
6. **`trade-core`, `trade-sdk` and their only importer, `apps/trade-lab`, are removed from the tree.** They were retired by d59 and unpublished on 2026-11-02, and they remain in the archive's history.

## Consequences

- **The next kernel fix publishes with provenance** once the founder has run the checklist (`docs/public-repository.md`, kept with the archive). Until then every instruction to a stranger keeps naming the versions on npm.
- **Two trees until the work moves.** After the public repository exists, kernel changes are made there first. A later prompt removes `packages/` from the archive and pins the sites to the published versions, as the engines already do (d10). Until then the export is re-run only by deliberate choice, never as a mirror.
- **The specification text and the rulebooks are CC BY 4.0, and the tooling is Apache-2.0** (d87(b)). No package is relicensed.
- **What stays private:** the sites, the labs, the services (kash-registry and kash-resolver are retired; muffler-pds is a server), the internal catalogue and brand packages, the OpenID Foundation run's logs and its harness (which boots Oreoasis's private engine), the internal audits and plans, and the closed-code specifications.
