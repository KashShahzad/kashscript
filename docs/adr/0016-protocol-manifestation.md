# ADR-0016: Protocol Manifestation — build the layer now; consumer-as-acceptance replaces trigger-gating

- **Status:** Accepted (2026-07-05) — **supersedes the trigger-table in [ADR-0015](0015-protocol-layer.md)**
- **Date:** 2026-07-05 (source: `ROADMAP.md` "the Manifestation", binding; `../ECOSYSTEM.md` decision 4 amendment)
- **Decision drivers:** founder decision to make Kashscript the active build focus; the ventures already contain working seed code for every protocol; premature-abstraction risk is now lower than divergence risk

## Context

[ADR-0015](0015-protocol-layer.md) recorded the protocol layer (Muffler / Whiffin / Hudhud) as
a **planning record** and gated each package behind an extraction trigger ("do not build until
the trigger fires"). That was the right posture while the ventures were pre-product and the
APIs were unknown.

On **2026-07-05** the founder changed the focus: Kashscript is now the active build target,
and the three ventures (Oreoasis, Duedale, Indusland) have each independently built the machinery
a protocol would own — DSSE signing, PDS read/write, grant/receipt mandates, an agent engine.
That machinery is duplicated three ways and drifting. The risk calculus flipped: the cost of
**divergence** (three incompatible implementations) now exceeds the cost of **premature
abstraction** that ADR-0015 was protecting against — *because the APIs are no longer unknown;
they are readable in the venture code.*

## Decision

**Build the full protocol layer now, in dependency order, deriving every API from the venture
code that seeds it.** The extraction trigger-gate of ADR-0015 is replaced by the:

> **Consumer-as-acceptance rule.** A protocol is DONE only when its venture consumer swaps onto
> the *published* package and stays green. The ventures are the API oracles — every protocol API
> is derived from the working venture code that seeds it, **never invented**. If a venture's
> test can't port cleanly, the protocol adapts, not the venture.

### Two standing guards

- **(a) Hudhud ships last.** Oreoasis is the selling venture; its engine must not be
  destabilised mid-pilot. The `oreoasis-core-host` → `@kashscript/hudhud` swap is **one atomic
  venture-side session**, scheduled around pilot activity, after `@kashscript/hudhud@0.1`
  publishes.
- **(b) Protocols must not absorb venture-specific code.** The seam rule in reverse: each
  phase's **"stays venture-side" list is binding**. Branded, single-consumer, or
  content/policy code stays in the venture.

### Target inventory + build order (M0 → M6)

| Package / service | Layer | Phase | Licence | Seeds from |
|---|---|---|---|---|
| identity-core, identity-sdk, identity-zkp, lexicons, kash | primitives | exist | Apache-2.0 | — |
| trade-core, trade-sdk | primitives | exist | Commercial (SSLA B) | — |
| neuron | primitive (becomes Hudhud's kernel) | exists | Commercial (SSLA B) | — |
| **`packages/attest`** | evidence commons | **M1** | **Apache-2.0** (verification is free — the trust posture) | Oreoasis `dsse`/witness/anchor + Duedale report + Indusland IPOE1/IVFC1 |
| **`packages/identity-server`** | identity completion | **M2** | Apache-2.0 | Duedale `identity-kernel` + Indusland JWKS route |
| **`packages/muffler`** | protocol: data | **M3** | Apache-2.0 | Indusland `@indus/muffler` + `identity-kernel` PDS r/w |
| **`services/muffler-pds`** | reference host (dev-grade) | **M3** | — | — |
| **`packages/whiffin`** | protocol: settlement | **M4** | Commercial (SSLA B) | Duedale `whiffin-gateway-sdk` + `duedale-core` grant + `ks-adapters` report |
| **`packages/hudhud`** | protocol: agents | **M5** | Commercial (SSLA B) | Oreoasis `oreoasis-core-host` engine |
| services/kash-registry, kash-resolver | services | exist | — | — |

**Publish order (dependency-first):** `attest → identity-server → muffler → whiffin → hudhud`.
No protocol publishes before its venture swap is proven locally (link/tarball per `LINKING.md`);
publish, then swap on the published version. `M6` makes the layer consumable by anyone (CLI
injection, licensing plumbing, audits, marketing flip).

### "Stays venture-side" per phase (binding — guard (b))

- **M1 attest:** issuance *policy* (who may sign what, when), storage adapters, JWKS hosting.
- **M2 identity-server:** Duedale's `DD_*` error mapping (ks-adapters), any app session logic.
- **M3 muffler:** `app.indusland.*` lexicons, `refine.ts` rules, `rm_*` projections, Supabase schema.
- **M4 whiffin:** `SegmentPolicy` content, `DD_*` envelopes, funder/vendor UI, the demo's SIMULATION posture.
- **M5 hudhud:** SOP *content*/workflow definitions, logistics fixtures, `chakor-text-ui`, client branding, positioning.

### Standards conformance (from `../ECOSYSTEM.md` decision 5 — consume standards, never invent)

- Agent auth → **MCP authorization = OAuth 2.1 + PKCE, audience-bound tokens**; `did:kash` roots mint them with agent→owner binding (M2).
- Mandates/credentials → **W3C Verifiable Credentials** with **AP2 mandate semantics** (M4).
- Evidence → **in-toto/DSSE** envelopes anchored to a transparency log (**Rekor** primary, **OpenTimestamps** fallback) (M1).
- Media provenance → **C2PA**; internal attestations (IPOE1) stay source of truth.
- Work certification → **AIUC-1** risk categories (M5).

### Licensing

attest / identity-server / muffler = **Apache-2.0** (identity + hosting stay free); whiffin /
hudhud = **Commercial, SSLA Schedule B**. `docs/legal/license-matrix.md` + `scripts/check-boundary.ts`
gain these rows at each package's creation (M6 finalises the tier mapping + kash-registry).

## Consequences

### Positive

- The three-way-duplicated machinery unifies into one audited implementation per concern.
- Every API is grounded in shipped venture behaviour, so extraction is a lift-and-align, not a redesign; the venture's own test suite is the acceptance oracle.
- The hudhud-last guard protects the revenue venture; the stays-venture-side lists prevent the protocols from bloating into venture logic.

### Negative / accepted trade-offs

- This is a large, multi-session program; until a phase's venture swap lands, that protocol is "published but unproven" and the ventures keep their seed code.
- Consumer-as-acceptance means real completion happens **venture-side** (in sibling repos), so each phase carries a flagged follow-up swap session outside this repo.
- Building five packages raises the versioning/publishing/audit surface (M6 absorbs the plumbing).

## Alternatives considered

- **Keep ADR-0015's trigger-gate** — rejected by the founder decision: the APIs are now known, and divergence cost exceeds abstraction cost.
- **Build all at once, no order** — rejected: `attest` is the dependency base (everything signs with it) and hudhud-last is a hard guard.
- **New repos per protocol** — rejected (ECOSYSTEM decision 3): protocols live inside Kashscript under `@kashscript/*` until an outside consumer requires a split.
