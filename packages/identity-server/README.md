# @kashscript/identity-server — the countersign ceremony, server identity, and the agent-identity profile

**Identity is free.** Apache-2.0. The server-side half of the Passport, the mechanic that gets a
second signature onto a record, and the auth surface agents talk to MCP servers with.

Built in phase **M2** of the protocol Manifestation
([ADR-0016](../../docs/adr/0016-protocol-manifestation.md)). Where
[`@kashscript/identity-core`](../identity-core) is pure `did:kash` crypto with no I/O, this package
is the **server** perimeter — and it adds a `did:kash`-rooted, **MCP-conformant** token for agents.
Every server-identity API is derived from the `@duedale/identity-kernel` seed; the agent-identity
profile is derived from the MCP authorization spec + its RFC stack — never invented. Full contract:
[`specs/identity-server.md`](../../specs/identity-server.md).

## Three layers

**1 · The countersign ceremony** — *a link, one click, signed. No install, no account, no password.*

A record signed only by the party it describes is self-attestation (ECOSYSTEM d26). This is how a
second, independent signature gets onto one — over **the byte-identical `PAE` bytes the first
signature covered**, so the result is an ordinary DSSE envelope with two entries in `signatures[]` and
**no new format for anything a member already signs**.

```ts
// the holder, who already signed something
const created = await createCountersignRequest({
  subject, requesterDid, requesterPrivateKey,
  statement: "Confirm you received the delivery for order A-77.",
  disclosures: [{ label: "Order", value: "A-77" }],
});
created.linkFor("https://your-own-host.example");  // or created.capabilitySecretB32, read aloud

// the counterparty, on their own device, with a key that never leaves it
const signingKey = await generateOneTimeSigningKey();
const { envelope, acceptance } = await acceptCountersignRequest({ request, subject, signingKey });
```

Four properties are load-bearing, not conveniences:

- **A signing DID is never reused across requesters.** With a wallet seed, it is derived per
  relationship (`HKDF` over a salt built from the **requester's** DID); without one, a fresh key per
  request. The counterparty contributes no stable input, so nothing about them links across books.
- **Declining records nothing at all** — no artifact, no store write, no state change. A decline is
  indistinguishable from silence.
- **Key custody travels inside the signed bytes.** A key somebody else minted is labelled
  `delegated-mint` and is **not subject-held**, permanently; `claimCountersignKey` moves future
  authority only.
- **There is no lookup.** The store has no listing, and acceptances are never persisted here — so
  *"what has this counterparty signed"* has nothing to answer with.

Verification is free and lives in [`@kashscript/attest`](../attest) (`attest verify bundle.json`, no
`--key`, no network). Spec: [`specs/countersign.md`](../../specs/countersign.md) · decision:
[ADR-0018](../../docs/adr/0018-countersign-primitive.md).

**2 · Server identity** (ported from the kernel seed, refit onto injectable stores)

- **Guest DIDs** — `issueGuestDid()`: server-generated Ed25519 keypair → self-certifying
  `did:kash`, private seed surrendered **once**, 7-day expiry cap. Never self-asserted.
- **Handshake** — `buildHandshakeChallenge()` (`chal_…`, 300 s) + one-time
  `consumeHandshakeChallenge()` + `verifyHandshakeSignature()` (DST-free raw Ed25519 / ECDSA-P256).
- **Resolution** — self-certifying `resolveDidPubkey()` (pubkey from `parseDid`; store gates
  `NOT_FOUND`/`REVOKED`) + `revokeGuestDid()`.
- **PDS contract** — `writePdsRecord()`/`readPdsRecord()` with content-addressed CIDs + optimistic
  revisions. The **durable** PDS is [`@kashscript/muffler`](../muffler) (M3); this ships the contract
  + an in-memory reference.
- `createIdentityServer({ challengeStore, metadataStore, pdsStore, countersignStore })` composes it
  into one instance. **Prisma/Redis/muffler adapters stay venture-side** — inject them via the store
  interfaces.

**3 · The agent-identity profile** (net-new, MCP-conformant)

A `did:kash` root ("owner") mints an OAuth 2.1 access token a delegated agent presents to an MCP
server:

```ts
const { token } = await mintAgentToken({
  owner: { did: ownerDid, privateKey },   // sub + signer (did:kash root)
  agent: agentDid,                        // act.sub — the agent→owner binding
  audience: "https://mcp.example.com/mcp",// aud (RFC 8707)
  issuer, clientId, scope, expiresInSeconds: 300,
});

const res = await verifyAgentToken(token, { expectedAudience: "https://mcp.example.com/mcp" });
// res.ok, res.audienceOk, res.ownerBinding = { owner, agent }
```

- **RFC 9068** JWT access token (`typ:"at+jwt"`, `alg:"EdDSA"`), signed raw-Ed25519 by the owner.
- **RFC 8707** `aud` audience binding — the MCP server MUST validate it is the audience
  (`verifyAgentToken` enforces it; wrong `aud` → `AUDIENCE_MISMATCH`).
- **RFC 8693** `act.sub` delegation — the agent acting for the owner.
- Signer key resolves via an explicit key, a **JWKS** `kid→x`, or — by default — the owner
  **`did:kash`** self-certifying (no network).
- **PKCE** S256 only (`pkce`), **JWKS** publish/parse public-only (`jwks`), RFC 8414 + 9728
  discovery metadata (`metadata`), RFC 8707 resource canonicalization (`agent/resource`).

## Provider-neutral

Errors are `KS_IDENTITY_*` codes only — a consuming venture maps them to its own envelope at its
perimeter (e.g. Duedale's `DD_*`). That mapping, the durable store adapters, and issuance policy
(rate-limits, denylists, origin allow-lists) **stay venture-side** (ADR-0016 guard b).

## Status

`0.x` — the API stays `0.x` until the venture consumer (Duedale) swaps onto the published package
and stays green (consumer-as-acceptance, ADR-0016). Depends on
[`@kashscript/identity-core`](../identity-core) + [`@kashscript/attest`](../attest).

Licensed Apache-2.0 — see `LICENSE`.
