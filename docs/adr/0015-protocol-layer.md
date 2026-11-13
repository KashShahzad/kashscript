# ADR-0015: Protocol layer (Muffler / Whiffin / Hudhud) — trigger-gated extraction, standards-conformant

- **Status:** **Superseded by [ADR-0016](0016-protocol-manifestation.md) (2026-07-05).** The
  extraction **trigger-table below is retired** — the founder replaced trigger-gating with the
  *consumer-as-acceptance* rule and the layer is now built in phases M0–M6. Retained for history;
  the **seed sources and standards-conformance commitments here still hold** (ADR-0016 carries them forward).
- **Date:** 2026-07-05 (source: `ROADMAP.md` P2, binding 2026-07-04)
- **Decision drivers:** the freeze rule (no speculative platform surface), avoiding premature API/version commitment, giving the ventures one shared target, standards-first interoperability

## Context

The Foundry's shape is **primitives → protocols → ventures** (ADR-0002 established the three
primitive artifacts; the marketing reframe of 2026-07-04 made the three layers explicit):

- **Primitives** ship today: identity (`@kashscript/identity-*`), trade
  (`@kashscript/trade-*`), neuron (`@kashscript/neuron`).
- **Ventures** are being built as real businesses: Indusland, Duedale, Oreoasis.
- Between them sits a **protocol layer** that today lives **embedded inside the ventures'
  own repos** — Indusland's `packages/muffler`, Duedale's `whiffin-gateway-sdk` +
  `identity-kernel`, Oreoasis's `apps/oreoasis-core-host`. It is real code solving real
  problems, but it is not yet a shared, versioned, published protocol.

Two forces pull in opposite directions. The **freeze rule** (ROADMAP standing rules: "no new
platform features not pulled by a venture") says do **not** extract these into `packages/*`
speculatively — a published protocol package is a standing versioning, API-stability, and
audit commitment, and an unused one is exactly the clutter `CLEANUP.md` exists to remove.
But leaving the decision unrecorded lets the three ventures **diverge** — each reinventing
PDS hosting, payments, or agent-runtime auth against a different target — so that a later
extraction has to reconcile three incompatible designs.

This ADR resolves that tension: **record the protocol layer now; extract later, per trigger.**

## Decision

Recognise **three protocols** as planned members of the layer. For each, fix its **seed**
(where the real code already lives), its **extraction trigger** (the concrete demand signal
that earns the package), and the **external standard it must conform to** (consume the
standard; do not invent a parallel scheme). **Do not create `packages/hudhud`,
`packages/muffler`, or `packages/whiffin` until that protocol's trigger fires.**

> ⛔ **Superseded (2026-07-05, ADR-0016).** The "do not create until the trigger fires" rule and
> the **Extraction trigger** column below no longer apply — the layer is being built now, phased,
> under consumer-as-acceptance. The **Seeds from** and **Conforms to** columns remain accurate.

| Protocol | Seeds from | Extraction trigger | Conforms to |
|---|---|---|---|
| **`packages/hudhud`** — agent runtime | Oreoasis `apps/oreoasis-core-host`: SOP compiler, scope-gating, MCP allowlist + circuit breaker, Ed25519 action ledger | Oreoasis engine **≥ 1 month churn-free under a paying client** | **MCP OAuth 2.1** for agent auth; **in-toto/DSSE** attestation envelope; **Rekor / OpenTimestamps** anchoring |
| **`packages/muffler`** — portable host / PDS | Indusland `packages/muffler` (`client.ts`, `cid.ts`, `indexer.ts`, sinks) + Duedale `identity-kernel` PDS read/write | A **second** real consumer of PDS hosting — e.g. Indusland operator-platform M2 **and** Oreoasis client-data need, both actual | **atproto-style PDS + firehose** (drop DWN); lexicon model already aligned (`@kashscript/lexicons`) |
| **`packages/whiffin`** — rail-agnostic payments | Duedale `whiffin-gateway-sdk` (`gateways` + `terminal`: Raast / EMVCo / Safepay / SoftPOS) | **First real money movement** in any venture (Duedale EMI settlement or Indusland bookings) | **AP2 mandate semantics as W3C VCs**; rails as adapters; **chain = one optional rail via `trade-sdk`** |

### Standards conformance (the load-bearing commitments)

- **Hudhud consumes the Model Context Protocol.** Agent authorization is **MCP OAuth 2.1**
  (OAuth 2.1 + PKCE, audience-bound tokens) — not a bespoke agent-auth scheme. Agent actions
  are wrapped in **in-toto/DSSE** signed attestation envelopes (DSSE = Dead Simple Signing
  Envelope) and anchored in a transparency/timestamp log (**Rekor** and/or
  **OpenTimestamps**) so the action ledger is externally verifiable, not self-attested. This
  is the productionised form of neuron's consequence-tiered, owner-signed, receipt-chained
  agency (ADR-0011); Hudhud is neuron's runtime, hardened and MCP-native.
- **Muffler converges on AT Protocol.** Adopt atproto's **PDS + firehose** model and
  **drop DWN** (the Web5 Decentralized Web Node line) — one storage/replication model, not
  two. This aligns with the PDS-sovereignty posture (ADR-0012) and the already-atproto-shaped
  lexicon framework (ADR-0006); the DID `@context` and lexicon `$id`s stay on bare
  `kashscript.com` hosts (ADR-0013).
- **Whiffin speaks AP2.** Payment intent is an **AP2 (Agent Payments Protocol) mandate
  expressed as a W3C Verifiable Credential** — the signed mandate is the source of truth
  regardless of how value moves. Settlement rails (Raast instant transfer, EMVCo QR,
  Safepay, SoftPOS, partner ledgers) are **pluggable adapters**; the blockchain is **one
  optional rail**, reached via `trade-sdk` (ADR-0010), never a requirement. This is the
  wire-format spine behind the rail-agnostic Whiffin story and satisfies Duedale's binding
  no-mandatory-chain doctrine.

Every protocol-level artifact remains a signed Kash-Event (ADR-0004): AP2 mandates, DSSE
attestations, and PDS records are all validated against lexicons (ADR-0006) and signed
against a `did:kash` (ADR-0003).

### Identity gains an agent-identity profile

The identity primitive adds an **agent-identity profile** (roadmap, not yet shipped): a
human's `did:kash` root **mints OAuth 2.1 / PKCE, audience-bound agent tokens with a
cryptographic agent → owner binding**. The Foundry **consumes the MCP authorization spec**
for this and does **not** invent a parallel auth scheme — so Hudhud's "MCP OAuth 2.1 for
agent auth" and identity's token-minting are the **same** mechanism seen from two ends. This
is how the public "agent identity / verifiable agent actions" framing is realised in
protocol terms: the owner stays the root of trust; the agent acts on scoped, revocable,
audience-bound delegations that trace back to a `did:kash`.

### Licensing posture (per ADR-0007)

- **Muffler → Permissive (Apache-2.0)** when extracted — it is an adoption layer; portable
  user hosting should be as unconditionally free as the identity primitive.
- **Whiffin, Hudhud → Commercial (SSLA Schedule B)** — they move money and operate agents on
  user data / carry operational cost, matching the commercial tier's rationale.

These entries join `docs/legal/license-matrix.md` and `scripts/check-boundary.ts` **only at
extraction time**, not before.

## Consequences

### Positive

- The three ventures build their embedded protocol code toward **one recorded target**
  (same auth spec, same PDS model, same mandate format), so extraction is a lift-and-align,
  not a three-way reconciliation.
- **No speculative package surface**: nothing to version, publish, audit, or keep
  green until a real consumer earns it — the freeze rule holds.
- **Standards-first** means interoperability and external auditability are designed in, not
  retrofitted — and the Foundry avoids maintaining bespoke auth/attestation/payment schemes.

### Negative / accepted trade-offs

- The protocol logic **lives duplicated inside the ventures** until extraction, so the seeds
  can drift from each other and from this ADR before they are unified. Mitigation: this ADR
  is the shared spec; revisit it when a trigger approaches.
- The **triggers are judgment calls** ("churn-free under a paying client", "first real money
  movement") — they require a human decision, not a CI check.
- The conformance targets are **external, evolving standards** (MCP, AP2, atproto, DSSE,
  Rekor). Pinning to them buys interop at the cost of tracking their churn.

## Alternatives considered

- **Extract the packages now** — rejected: violates the freeze rule, commits to APIs before a
  second consumer exists, and ships unused surface (the clutter `CLEANUP.md` removes).
- **Never formalise the layer** — rejected: the ventures would diverge onto incompatible
  designs, making any future extraction a costly reconciliation.
- **Invent Foundry-native auth / payment / storage schemes** — rejected: bespoke security
  protocols are a liability; consuming MCP OAuth 2.1, AP2/W3C-VC, and atproto PDS gives
  audited, interoperable foundations and keeps the Foundry's own surface small.

## References

- `ROADMAP.md` P2 (source, binding) · standing rules (freeze, license posture)
- ADR-0002 (three-artifact layering) · ADR-0003 (`did:kash`) · ADR-0004 (Kash-Event) ·
  ADR-0006 (lexicons) · ADR-0007 (dual-tier licensing) · ADR-0010 (trade kernel/SDK split) ·
  ADR-0011 (neuron v2 accountable agency) · ADR-0012 (PDS data sovereignty) · ADR-0013
  (host/namespace hygiene)
- External: Model Context Protocol (authorization) · OAuth 2.1 + PKCE · in-toto / DSSE ·
  Sigstore Rekor · OpenTimestamps · AT Protocol (PDS + firehose) · W3C Verifiable
  Credentials · AP2 (Agent Payments Protocol)
