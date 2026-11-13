# `@kashscript/identity-server` — server identity + the agent-identity profile

**`specs/identity-server.md` — v0.1 · BUILT in M2 · red-team audited round 1 (M6). Apache-2.0.**

> **Security:** [`identity-server-audit-r1.md`](identity-server-audit-r1.md). The **Critical** JWKS
> owner-impersonation finding (F1) is fixed — the signer key is resolved by the owner `sub`, not the
> attacker-controlled `kid` — along with F2 (non-did `sub`/`act.sub`) and F5 (unbounded clock skew); F3
> (issuer trust) + F4 (replay/revocation hooks) logged.

> Status: **draft — built, consumer-acceptance pending.** The package is implemented and its own
> test suite is green (M2, [ADR-0016](../docs/adr/0016-protocol-manifestation.md)), but per the
> consumer-as-acceptance rule the API stays `0.x` until its venture consumer (Duedale) swaps onto
> the published package and stays green. Every server-identity API is **derived from the venture
> seed** (`@duedale/identity-kernel`); the agent-identity profile is **derived from the MCP
> authorization spec + its RFC stack**, never invented. **Licence: Apache-2.0 — identity is free.**

## Purpose

Two layers a venture needs at the identity perimeter that the primitive `@kashscript/identity-core`
(pure `did:kash` crypto, no I/O) deliberately does not host:

1. **Server identity** — server-issued **guest DIDs**, **handshake** challenge/response,
   self-certifying **DID resolution**, and the **PDS** read/write contract. Ported from the
   `@duedale/identity-kernel` seed, refit from `NotImplemented` shells into real, injectable,
   store-backed implementations.
2. **The agent-identity profile** — a `did:kash` root ("owner") minting **OAuth 2.1 + PKCE**,
   **audience-bound**, **agent→owner-delegated** access tokens for agents talking to MCP servers.
   This is the auth surface `@kashscript/hudhud` (closed code inside Oreoasis since 2026-11-02) consumes in M5.

It sits second in the publish order: `attest → identity-server → muffler → whiffin → hudhud`.
It depends only on `@kashscript/identity-core` (DID + keys) and `@kashscript/attest` (raw-Ed25519
JWS signing + SHA-256).

## Seeds (the API oracles — M2 derives from these)

- **Duedale `packages/identity-kernel/src/{index,types,errors}.ts`** — the full server-identity
  surface (11 runtime + 24 type + 4 error exports). `verifyHandshakeSignature`, `issueGuestDid`,
  and the `sha256Hex*` helpers are implemented end-to-end against WebCrypto; the five
  transport-bound functions are `NotImplemented` shells whose real logic lives in the Prisma/Redis
  `ks-adapters` bridge. identity-server ports the implemented ones **verbatim** and turns the
  shells into store-backed implementations (interfaces + `InMemory*` reference).
- **Indusland verifier JWKS route** — the public-only Ed25519 JWK Set wire shape
  (`{kty:"OKP",crv:"Ed25519",x,kid,use:"sig",alg:"EdDSA"}`, `application/jwk-set+json`,
  `cache-control: public, max-age=3600`, private `d` rejected).
- **The MCP authorization spec** (OAuth 2.1 draft) + RFCs 9068 / 8707 / 8693 / 7636 / 8414 / 9728 /
  9207 / 7517 / 7800 / 6750 — the derivation source for the agent token (below). Conform, don't invent.

## Layer 1 — server identity surface (kernel-ported)

| Export | Kind | Notes |
|---|---|---|
| `issueGuestDid(request)` | storeless | Custodial-at-mint, **non-persisting**: generates the Ed25519 keypair, derives `did:kash`, surrenders the 32-byte private seed **once**, caps expiry at 7 days. |
| `verifyHandshakeSignature({challenge, signatureB64, algorithm, publicKeyB64})` | storeless | Ported byte-for-byte: **DST-free** raw-payload verify, ordered expiry→format→zero-length→key-import→verify, raw-or-SPKI Ed25519 + ECDSA-P256, `SPOOFED_SIGNATURE` on crypto mismatch. |
| `buildHandshakeChallenge(did)` | storeless | `chal_<hex>` id, 32 random payload bytes, **300 s** TTL. |
| `sha256HexOfBase64` / `sha256HexOfUtf8` | storeless | Lowercase-hex digests via attest's `sha256Hex`. |
| `SUPPORTED_ALGORITHMS` | const | `["ed25519","ecdsa-p256"]`. |
| `probeAvailability()` | diag | `{ available:true, reason:"READY", version, cryptoBackend:"WEB_CRYPTO" }`. |
| `createIdentityServer({challengeStore, metadataStore, pdsStore})` | factory | Returns an `IdentityServer` whose methods (`issueGuestDid`, `issueHandshakeChallenge`, `consumeHandshakeChallenge` [one-time], `resolveDidPubkey`, `revokeGuestDid`, `writePdsRecord`, `readPdsRecord`) match the kernel signatures. Omitted stores default to `InMemory*`. |
| `ChallengeStore` / `IdentityMetadataStore` / `PdsStore` | interfaces | The injected durable dependencies. `InMemory*` reference impls ship for tests/dev; **Prisma/Redis and the durable PDS ([muffler](muffler.md), M3) stay venture-side.** |
| `resolveDidPubkey` / `revokeGuestDid` / `writePdsRecord` / `readPdsRecord` | store-taking fns | The same operations as free functions taking a store, for composition. |

DID resolution is **self-certifying**: the pubkey is extracted from the `did:kash` via `parseDid`
(never trusted from client input); the metadata store supplies the mutable envelope
(`isGuestDid` / `expiresAtUnix` / `pdsEndpoint` / revocation) and gates `NOT_FOUND` / `REVOKED`.

## Layer 2 — the agent-identity profile (MCP-conformant)

An owner `did:kash` mints an OAuth 2.1 access token that a **delegated agent** presents to an MCP
server. The token is a compact JWS (`header.payload.signature`), signed with **raw Ed25519**
(`attest.signRaw`) by the owner's root key.

### Token claims

| Claim | Source | Meaning |
|---|---|---|
| `typ` (header) | RFC 9068 | `"at+jwt"` — JWT access-token profile. |
| `alg` (header) | — | `"EdDSA"`. `kid` defaults to the owner `did:kash`. |
| `iss` | — | AS issuer: an https URL (hosted discovery) **or** the owner `did:kash` (self-sovereign). |
| `sub` | — | The **owner** — a `did:kash` root. The token principal + the signing identity. |
| `aud` | **RFC 8707** | The MCP server's **canonical resource URI**. The server MUST validate it is the audience. |
| `act.sub` | **RFC 8693** | The **agent** acting for `sub`. **This is the agent→owner binding.** |
| `client_id`, `scope` | OAuth 2.1 | The agent's client id + granted scopes. |
| `iat`, `exp`, `jti` | RFC 7519 | Issued-at, expiry, unique id. |
| `cnf` | RFC 7800 | Optional proof-of-possession key binding. |

### `verifyAgentToken(token, opts)`

Enforces, in order: header discipline (`at+jwt` / `EdDSA`) → signer-key resolution → **JWS
signature** → owner→agent binding extraction → temporal (`exp`/`nbf`) → optional issuer →
**RFC 8707 audience** (confused-deputy defence). Returns
`{ ok, reason, claims, audienceOk, ownerBinding:{owner, agent}, traceId }` — never throws for a
well-formed-but-invalid token. **Signer-key resolution is three-way**, in priority order:

1. an explicit `publicKey`,
2. a **JWKS** `kid → x` lookup (`opts.jwks`),
3. by default, the **self-certifying** owner `did:kash` (`sub`) via `parseDid` — **no network, no
   key registry**.

### Supporting surface

- **PKCE (`pkce.ts`)** — **S256 only** (OAuth 2.1 / MCP forbid `plain`): `generateCodeVerifier`,
  `codeChallengeS256` = `BASE64URL(SHA-256(verifier))`, `verifyPkce` (constant-time). Verified
  against the RFC 7636 Appendix B vector.
- **JWKS (`jwks.ts`)** — `publishJwks` / `jwkFromEd25519PublicKey` emit the Indus wire shape;
  `parseJwks` **rejects any key carrying a private `d`**; `publicKeyFromJwks` resolves `kid → key`.
- **Discovery metadata (`metadata.ts`)** — `buildAuthorizationServerMetadata` (RFC 8414;
  `code_challenge_methods_supported:["S256"]`, `authorization_response_iss_parameter_supported:true`
  per RFC 9207) and `buildProtectedResourceMetadata` (RFC 9728). Plain objects for the venture's
  `.well-known` routes.
- **Resource canonicalization (`agent/resource.ts`)** — RFC 8707: absolute URI, **no fragment**,
  lowercase scheme+host, default port + bare trailing slash dropped. Both the minted `aud` and the
  resource server's expected identifier run through it, so `:443`/trailing-slash variants compare equal.

## Stays venture-side (guard b, ADR-0016)

The `DD_*` (or any provider-specific) error mapping — identity-server emits only provider-neutral
`KS_IDENTITY_*` codes; the Prisma/Redis store **adapters** (the interfaces' durable impls); the
durable PDS itself ([muffler](muffler.md), M3); issuance **policy** (guest-DID rate-limiting,
denylisting, origin allow-listing, CAPTCHA — the `IssueGuestDidFailureReason` variants); and app
session logic.

## Done when

1. **identity-kernel's export surface fully covered** — a coverage test asserts every runtime / type
   / error export has an equivalent (module-level or as an `IdentityServer` method) + behaves
   (guest-DID mint, handshake issue→consume(one-time)→verify, resolve `NOT_FOUND`/`REVOKED`, revoke +
   `NOT_A_GUEST_DID`, malformed-DID throws, PDS write/read/revision). ✅
2. **Agent-token round-trip** — owner `did:kash` mints (`aud`=resource, `sub`=owner, `act.sub`=agent)
   → audience-check passes for the right `aud`, **rejects** a wrong `aud` (RFC 8707) → owner-binding
   verify extracts `{owner, agent}` and the JWS verifies under the owner key **via JWKS and via
   did:kash self-certifying resolution**. ✅
3. **PKCE** S256 (RFC 7636 vector) + **JWKS** public-only shape tests. ✅
4. `typecheck` + `test` + `check-boundary.ts` + full-workspace typecheck green. ✅
5. **Venture-side follow-up (post-publish):** the Duedale swap wires `createIdentityServer` to its
   Prisma/Redis stores and deletes `identity-kernel` (consumer-as-acceptance closes M2).

## Change Log

| Version | Date | Summary |
|---|---|---|
| **v0.2.0** | 2026-09-22 | **The countersign ceremony** — ECOSYSTEM decision 26's mechanic: a link, one click, signed, with no install, account or password. Adds `createCountersignRequest` / `acceptCountersignRequest` / `declineCountersignRequest` / `withdrawCountersignRequest` / `claimCountersignKey`, per-relationship signing keys (HKDF; d41), the branding-free ceremony page (d44), and a `CountersignRequestStore` with no listing and no persisted acceptances. The artifact format and its free verifier live in `@kashscript/attest`. Spec: [`countersign.md`](countersign.md) · decision: [ADR-0018](../docs/adr/0018-countersign-primitive.md). 81 tests green. **Not published.** |
| **v0.1 · audit r1** | 2026-07-05 | Round-1 red-team audit (M6): Critical F1 (JWKS/explicit-key not bound to `sub` → owner impersonation) fixed by resolving the signer key via `sub`; F2 (non-did `sub`/`act.sub`) + F5 (unbounded clock skew) fixed; F3/F4/F6 logged. 45 tests green. See [`identity-server-audit-r1.md`](identity-server-audit-r1.md). |
| **v0.1** | 2026-07-05 | Built in M2 (ROADMAP Manifestation). Ported the `@duedale/identity-kernel` surface into real store-backed implementations; added the net-new agent-identity / MCP-OAuth token profile (RFC 9068 + 8707 + 8693 + 7636 + 8414 + 9728). 41 tests green. API stays `0.x` pending the Duedale consumer swap. |
