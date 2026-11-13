# Security baseline and scope — the KashScript open protocol

The reporting policy (contact, timings, safe harbour, scope) is [SECURITY.md](../../SECURITY.md),
one text for all five repositories of the ecosystem. This file holds what is specific to this one.

## Scope

In scope here: the twelve `@kashscript/*` packages in this repository and their published versions.
We most want to hear about anything that lets a record **pass a check it should fail**: a forged or
re-bound signature, an issuer not bound to its key, a countersignature counted twice, a disclosure
proof that verifies without the commitment, a rule that grants what its criteria refuse.

A useful report includes the package and version, a minimal reproduction (a failing test is best),
the class of bug, and your view of its severity.

## Supported versions

Security fixes ship in a new version of the affected package. `latest` and `alpha` move to it, and
the release note names what it fixes. Pre-1.0 packages may change their API in a security fix; the
release note says so. Earlier versions are not patched.

## How this repository guards itself

- **Every package's own suite** runs on every push and pull request, and again before any publish.
- **Secret scanning:** gitleaks on every push and over the whole history weekly (`.gitleaks.toml`).
  The history starts clean.
- **Static scanning:** Semgrep's community rules on every push.
- **Nothing closed enters:** `scripts/check-public-tree.ts` refuses closed or private paths;
  `scripts/check-boundary.ts` refuses a package whose licence, publish configuration or repository
  field is wrong.
- **Publishing** only from `.github/workflows/publish.yml`, through npm's trusted publishing (OIDC, no
  long-lived token), with provenance, a CycloneDX SBOM per package and a Sigstore-signed release
  ([docs/publishing.md](../publishing.md)).
- **Dependencies:** Dependabot proposes the bumps; every third-party action is pinned to a commit SHA.
