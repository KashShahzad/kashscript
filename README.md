# KashScript — the open protocol

Twelve packages for issuing, holding and checking signed records: identity keys, evidence bundles,
the holder's wallet, countersigning, rules and agreements. Each is published to npm under
`@kashscript/*` and licensed under Apache-2.0.

**Checking never needs us.** A record carries its signatures, and the verifier runs offline on your own
machine. Nothing here searches for people, scores them or moves money.

## The packages

| Package | What it does |
|---|---|
| [`@kashscript/identity-core`](packages/identity-core) | Keys, `did:kash` documents, canonical JSON (JCS) and signed events. No network, no storage |
| [`@kashscript/lexicons`](packages/lexicons) | The record envelope, schema language, registry and validator |
| [`@kashscript/attest`](packages/attest) | Evidence bundles: DSSE envelopes, witnessing, hash chains, and a standalone offline verifier (`npx @kashscript/attest verify`) |
| [`@kashscript/identity-sdk`](packages/identity-sdk) | Passkey sign-in for `did:kash`, as a React provider and hooks |
| [`@kashscript/identity-zkp`](packages/identity-zkp) | Selective disclosure by Merkle commitments, and a zero-knowledge prover and verifier |
| [`@kashscript/identity-server`](packages/identity-server) | Server-side identity: guest DIDs, the handshake, DID resolution, JWKS |
| [`@kashscript/muffler`](packages/muffler) | A client for public, organisation-authored records, with a firehose indexer |
| [`@kashscript/terms`](packages/terms) | Agreements with a declared split, as a deterministic state machine. It holds no balance |
| [`@kashscript/predicate`](packages/predicate) | The rule engine: a rule's criteria as OpenID4VP DCQL queries plus FEEL conditions |
| [`@kashscript/wallet`](packages/wallet) | The holder's wallet component: keys first, no account; receives, holds, presents and exports records |
| [`@kashscript/whiffin`](packages/whiffin) | Purpose-bound mandates. It never moves money |
| [`@kashscript/kash`](packages/kash) | The `kash` CLI: a station's own keys, issuing and countersigning records as files, checking them |

The specifications are in [`specs/`](specs), the decision records in [`docs/adr/`](docs/adr), and
open rulebooks in [`docs/rulebooks/`](docs/rulebooks).

## Working on it

```bash
bun install --frozen-lockfile
bun run typecheck
bun scripts/test-packages.ts            # every package's own suite, one after another
bun scripts/test-packages.ts --only attest
```

The packages need Bun 1.2.5 or later. Every package's suite runs in CI on every push.

## Publishing

Packages are published only from [`.github/workflows/publish.yml`](.github/workflows/publish.yml).
It uses npm's trusted publishing (OIDC, no long-lived token) with provenance, attaches a CycloneDX
SBOM to each package, and makes a Sigstore-signed GitHub release. Each version's provenance names the
commit it was built from. [`docs/publishing.md`](docs/publishing.md) describes the path.

## Licence, contributions, security

- Every package is Apache-2.0; see [LICENSE](LICENSE) for the rest of the repository.
- Contributions need a signed contributor licence agreement first: [CONTRIBUTING.md](CONTRIBUTING.md) and [CLA.md](CLA.md).
- Report anything exploitable privately, as [SECURITY.md](SECURITY.md) says, never in a public issue.

This repository starts from a clean history. The packages' earlier development happened in a private
repository, and the versions published from it went out without provenance.
