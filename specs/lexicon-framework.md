# Kash Lexicon Framework — Developer Guide
**`specs/lexicon-framework.md` — v1.0 · How to design, register, and evolve a lexicon**

> **Update note (2026-05-28):** three new domain extensions shipped
> (`/extensions/education`, `/extensions/civic`, `/extensions/community`)
> totalling six new schemas (`kash.education.transcript`, `peer-review`,
> `kash.civic.permit`, `petition`, `kash.community.membership`,
> `aid-claim`). Shipped as lexicons@0.1.1. Versioning + migration
> playbook now lives at [`docs/lexicon-versioning.md`](../docs/lexicon-versioning.md).
> Full delta in `specs/audit-2026-05-28-updates.md` (an internal change log, not in the public repository) §4.

> Lexicons are the **strictly-typed schemas** that records in a PDS conform to. This guide is for application developers who want to define their own lexicons (e.g., `app.indusland.post`, `app.duedale.listing`) on top of the Kash protocol.
>
> The runtime implementation lives in [`@kashscript/lexicons`](../packages/lexicons/). It is **zero-dependency**: pure data modelling and validation, no network or storage code.
>
> Read first: [Identity Bible v1.0](./identity-protocol-v1.md) — §3 (DID Document), §5 (Handshake), §5.5 (DST register), §6 (PDS + Lexicon hooks).

---

## 0. Quick Start — Define Your First Lexicon

Five steps. The example: a `app.duedale.listing` lexicon for a Duedale marketplace listing.

```typescript
// packages/duedale-app/src/lexicons/listing.ts
import { S, type ObjectSchema, type LexiconDef } from "@kashscript/lexicons";

// 1. Pick an NSID + version
export const LISTING_NSID    = "app.duedale.listing" as const;
export const LISTING_VERSION = { major: 1, minor: 0, patch: 0 } as const;
export const LISTING_ID      = "app.duedale.listing@1.0.0" as const;

// 2. Define the TypeScript interface
export interface ListingBody {
  readonly title:       string;
  readonly description: string;
  readonly priceMinor:  number;       // smallest currency unit (paisa, cents)
  readonly currency:    string;       // ISO 4217
  readonly category:    "goods" | "services" | "rentals";
  readonly photos?:     readonly { readonly cid: string; readonly mimeType: string }[];
  readonly closedAt?:   string;       // ISO-8601; absent = open
}

// 3. Define the runtime schema (mirrors the interface)
const LISTING_PHOTO: ObjectSchema = S.object(
  {
    cid:      S.string({ format: "cid" }),
    mimeType: S.enum("image/jpeg", "image/png", "image/webp"),
  },
  ["cid", "mimeType"],
);

export const LISTING_BODY_SCHEMA: ObjectSchema = S.object(
  {
    title:       S.string({ minLength: 1, maxLength: 140 }),
    description: S.string({ minLength: 1, maxLength: 4000 }),
    priceMinor:  S.number({ integer: true, min: 0 }),
    currency:    S.string({ format: "iso4217" }),
    category:    S.enum("goods", "services", "rentals"),
    photos:      S.optional(S.array(LISTING_PHOTO, { maxItems: 8 })),
    closedAt:    S.optional(S.string({ format: "iso8601" })),
  },
  ["title", "description", "priceMinor", "currency", "category"],
);

// 4. Export a LexiconDef so consumers can register it
export const LISTING_DEF: LexiconDef = {
  id:          LISTING_ID,
  nsid:        LISTING_NSID,
  semver:      LISTING_VERSION,
  bodySchema:  LISTING_BODY_SCHEMA,
  title:       "Duedale Listing",
  description: "A single marketplace listing on Duedale.",
};
```

```typescript
// 5. Register + validate at app bootstrap
import { LexiconRegistry, validateEvent, STANDARD_LIBRARY } from "@kashscript/lexicons";
import { TRADE_EXTENSION } from "@kashscript/lexicons/extensions/trade";
import { LISTING_DEF } from "./lexicons/listing";

const registry = new LexiconRegistry()
  .registerAll(STANDARD_LIBRARY)     // identity-tier lexicons (always available)
  .registerAll(TRADE_EXTENSION)      // opt-in: trade domain
  .register(LISTING_DEF);            // your app-specific lexicon

const result = validateEvent<ListingBody>(envelopeFromPds, registry);
if (!result.ok) {
  console.error("rejected:", result.errors);
} else {
  // result.value is typed as KashEvent<ListingBody>
}
```

That's the entire authoring path. The rest of this guide explains the rules behind each step.

### 0.1 Box-vs-Content Separation

`@kashscript/lexicons` is built around a strict separation:

- **The Box** — framework primitives (`Schema`, `S` DSL, `KashEvent` envelope, `LexiconRegistry`, `validateEvent`, `getSchemaDefinition`). Knows nothing about any specific domain.
- **The Content** — actual lexicon definitions. Ships in three flavours:
  - **Standard Library** — identity-tier lexicons (`kash.id.*`). Exported from the main package; every Kash actor needs them.
  - **Extensions** — domain lexicons (`kash.social.*`, `kash.trade.*`). Subpath imports — `@kashscript/lexicons/extensions/social` and `/extensions/trade`. **Not auto-loaded.**
  - **Third-party content** — your `app.*` lexicons (see §13).

A consumer that wants a pure-identity product imports only the main package and registers `STANDARD_LIBRARY`. Domain content is opt-in. This is the load-bearing rule that makes the framework sellable as an agnostic infrastructure layer.

---

## 1. Glossary (Quick Reference)

| Term         | Definition                                                              |
|--------------|-------------------------------------------------------------------------|
| **NSID**     | Reverse-DNS identifier — `app.duedale.listing`.                         |
| **Lexicon ID**| NSID@semver — `app.duedale.listing@1.0.0`.                             |
| **Envelope** | The `KashEvent<Body>` wrapper around every record (header + body + sig).|
| **Body**     | Lexicon-specific payload inside the envelope.                           |
| **Schema**   | The runtime validator definition for a body (`@kashscript/lexicons` DSL).|
| **DST**      | Domain-Separation Tag — `kash-record-v1\n` for record signatures.       |
| **NSID root**| First segment — owned by a registered namespace owner.                  |

---

## 2. NSID — Naming & Namespace Reservation

### 2.1 Format

Reverse-DNS, all lowercase, ASCII letters, digits, hyphens. Segments separated by `.`:

```
<root>.<sub>.<...>.<name>
```

- The first segment is a **registered root**.
- Subsequent segments are app- or org-defined.

### 2.2 Registered Roots

| Root            | Owner                            | Examples                                               |
|-----------------|----------------------------------|--------------------------------------------------------|
| `kash.id.*`     | `@kashscript/identity-core`           | `kash.id.profile`, `kash.id.audit`, `kash.id.preferences` |
| `kash.trade.*`  | `@kashscript/trade-core`              | `kash.trade.listing`, `kash.trade.escrow`              |
| `kash.neuron.*` | `@kashscript/neuron`             | `kash.neuron.context-grant`, `kash.neuron.signal`      |
| `kash.lexicon.*`| Meta — lexicons describing lexicons | `kash.lexicon.definition`                          |
| `app.<name>.*`  | Third-party apps                 | `app.indusland.post`, `app.duedale.listing`            |

> **Squatting prohibited.** If you are building an app, use `app.<your-app-name>.*`. The `kash.*` roots are reserved for protocol-level types.

### 2.3 Pick a Good NSID

- **Be specific.** `app.duedale.listing` is better than `app.duedale.data` — a verifier can decide what to do with a *listing* but not generic *data*.
- **One concept per NSID.** Don't pack listings and disputes into the same lexicon; use `app.duedale.listing` and `app.duedale.dispute`.
- **Lowercase only.** `App.Duedale.Listing` is rejected by the validator.

---

## 3. Versioning — Semver Within the Lexicon ID

### 3.1 The Rules

| Bump  | Allowed change                                                              | Existing records valid? |
|-------|-----------------------------------------------------------------------------|-------------------------|
| PATCH | Documentation / non-normative clarifications only.                          | ✅ Yes                   |
| MINOR | Add **optional** fields; relax constraints; add new enum members.           | ✅ Yes                   |
| MAJOR | Remove fields; rename fields; tighten constraints; add **required** fields. | ❌ No — migration needed |

### 3.2 Forward Compatibility (Within Major)

A consumer registered for `<nsid>@X.Y.Z` will accept **any** record minted with `<nsid>@X.*.*`. The validator picks the highest registered version whose major matches.

```typescript
// You register: app.duedale.listing@1.2.0
// You may also register: app.duedale.listing@2.0.0 (alongside)
// Records minted with 1.0.0, 1.1.0, 1.2.0, 1.3.5 → match v1.2.0
// Records minted with 2.0.0, 2.1.0                → match v2.0.0
// Records minted with 0.9.0 (no v0.* registered)  → rejected
```

### 3.3 What Counts as Each Bump

```typescript
// v1.0.0 — initial
export const LISTING_BODY_SCHEMA = S.object({
  title:       S.string({ minLength: 1, maxLength: 140 }),
  priceMinor:  S.number({ integer: true, min: 0 }),
}, ["title", "priceMinor"]);

// v1.1.0 — MINOR: added optional "tags" field
export const LISTING_BODY_SCHEMA_v1_1 = S.object({
  title:       S.string({ minLength: 1, maxLength: 140 }),
  priceMinor:  S.number({ integer: true, min: 0 }),
  tags:        S.optional(S.array(S.string({ maxLength: 32 }), { maxItems: 16 })),
}, ["title", "priceMinor"]);

// v2.0.0 — MAJOR: renamed "priceMinor" → "priceCents"; added required "currency"
export const LISTING_BODY_SCHEMA_v2 = S.object({
  title:       S.string({ minLength: 1, maxLength: 140 }),
  priceCents:  S.number({ integer: true, min: 0 }),
  currency:    S.string({ format: "iso4217" }),
}, ["title", "priceCents", "currency"]);
```

### 3.4 Anti-Patterns

- ❌ **Tightening a constraint as a MINOR bump.** Going from `maxLength: 280` to `maxLength: 140` invalidates existing records. This is MAJOR.
- ❌ **Adding a required field as a MINOR bump.** Existing records lack it. MAJOR.
- ❌ **Removing an optional field as a MINOR bump.** Consumers that read the field break. MAJOR.
- ✅ **Renaming an optional field by adding the new name + keeping the old.** Old name is deprecated; remove in next MAJOR.

---

## 4. The Envelope — What Wraps Every Record

Every record looks like this:

```jsonc
{
  "header": {
    "did":     "did:kash:5g7q2hvh3xkvjnq7tzaaymzfeswftxnnyya",
    "lexicon": "app.duedale.listing@1.0.0",
    "iat":     "2026-05-09T12:34:56Z",
    "nonce":   "a1b2c3d4e5f6…",       // 32-128 hex chars
    "cid":     "bafyreid…",            // multihash of JCS(body)
    "seq":     14,                     // optional
    "prev":    "bafyreic…",            // optional
    "rkey":    "3jzfcijpj2v2g"         // optional
  },
  "body": { /* lexicon-specific */ },
  "signature": {
    "kid": "did:kash:5g7q…#sig-1",
    "alg": "ed25519",
    "sig": "z3jK8…",
    "dst": "kash-record-v1\n"
  }
}
```

**You only design the `body`.** The envelope is governed by `KashEvent<Body>` from `@kashscript/lexicons/envelope` and is identical for every lexicon.

### 4.1 Signed Bytes

```
sig = Sign[alg]( sk_active , "kash-record-v1\n" || JCS({ header, body }) )
```

- DST is fixed; you don't pick it.
- Body bytes go through JCS (RFC 8785) before hashing or signing.
- `cid` is computed from `body` alone (so two envelopes wrapping the same body share a CID).

### 4.2 The Nonce

A random 128-bit (or larger) hex string. Required. Its purpose is **uniqueness** within `(did, lexicon)` — two records that would otherwise be byte-identical (same body, same `iat`) still have distinct CIDs because their nonces differ.

> Note: the nonce is **not** an anti-replay measure for the handshake (that's `nonce + audience` per Identity Protocol §5.3). The record nonce is solely for content-address uniqueness.

---

## 5. Designing a Body Schema — The `S` DSL

`@kashscript/lexicons` exposes a Zod-style builder under the `S` namespace. Every helper returns a plain-data schema — no closures, no class instances — so schemas are trivially serialisable and inspectable.

### 5.1 Primitives

```typescript
S.string({ minLength: 1, maxLength: 140 })
S.string({ pattern: /^[A-Z0-9_]+$/ })
S.string({ format: "cid" })              // built-in: cid, did-ks, iso8601, url, multibase, bcp47, iso4217, lexicon-id, nsid
S.number({ integer: true, min: 0, max: 1_000_000 })
S.boolean()
S.literal("v1")
S.literal(42)
S.literal(null)
S.enum("light", "dark", "system")
```

### 5.2 Composites

```typescript
S.array(S.string(), { minItems: 1, maxItems: 16 })

S.object(
  {
    title: S.string({ minLength: 1, maxLength: 140 }),
    body:  S.string({ maxLength: 4000 }),
  },
  ["title"],                              // required
  false,                                  // additionalProperties (default false)
)

S.union(
  S.literal("draft"),
  S.literal("published"),
  S.object({ kind: S.literal("scheduled"), at: S.string({ format: "iso8601" }) }, ["kind", "at"]),
)

S.optional(S.string({ maxLength: 280 }))

S.record(S.string({ maxLength: 1000 }))   // Record<string, string-≤1000>
```

### 5.3 String Formats (Built-in)

| Format       | Example                                                                  |
|--------------|--------------------------------------------------------------------------|
| `cid`        | `bafyreid…` (CIDv1 base32)                                              |
| `did-ks`     | `did:kash:5g7q2hvh3xkvjnq7tzaaymzfeswftxnnyya`                            |
| `iso8601`    | `2026-05-09T12:34:56Z`                                                  |
| `url`        | `https://example.com/path`                                              |
| `multibase`  | `z3jK8…`                                                                 |
| `bcp47`      | `en`, `ur-PK`                                                            |
| `iso4217`    | `USD`, `PKR`                                                             |
| `lexicon-id` | `app.duedale.listing@1.0.0`                                              |
| `nsid`       | `app.duedale.listing`                                                    |

Need a custom format? Pass a `pattern: RegExp` instead.

### 5.4 Strict by Default

The validator rejects unknown fields. To allow them (e.g., for forward-compat with future minor bumps), opt in:

```typescript
S.object({ a: S.string() }, ["a"], true);   // additionalProperties: true
```

> Recommendation: **leave `additionalProperties: false` (default) on bodies you own.** Forward-compat is achieved by adding fields in your next MINOR version, not by accepting arbitrary fields.

---

## 6. Common Patterns

### 6.1 Single-Record Collection (`rkey: "self"`)

Used for: profile, preferences — exactly one record per (DID, lexicon).

```typescript
// rkey convention
{ rkey: "self" }
```

Validator + storage layer enforce singleton at PUT time (Phase-3 PDS implementation).

### 6.2 Append-Only Collection (audit log)

Used for: identity audit, payment log, dispute trail. Records use `seq` + `prev` to form a chain.

```typescript
{
  seq: 14,
  prev: "bafyreic…"    // CID of seq=13 record
}
```

The `KASH_AUDIT_BODY_SCHEMA` in this package is a reference implementation.

### 6.3 Per-Record Collection (posts, listings)

Used for: anything where a user mints many independent records. `rkey` is a TID (timestamped identifier) or app-chosen string.

```typescript
{ rkey: "3jzfcijpj2v2g" }   // TID
```

No `seq`/`prev`. Each record stands alone.

### 6.4 Reference Patterns

References by CID (preferred when content matters):

```typescript
{
  parentCid: S.string({ format: "cid" }),     // points to a specific version of the parent
}
```

References by URI (when you want the "latest"):

```typescript
{
  parentUri: S.string({ pattern: /^at:\/\// }), // points to a (DID, NSID, rkey) tuple — resolves to current head
}
```

References by DID (when pointing to an actor):

```typescript
{
  mentionedDid: S.string({ format: "did-ks" }),
}
```

### 6.5 Embedded Blobs

```typescript
{
  image: S.object(
    {
      cid:      S.string({ format: "cid" }),
      mimeType: S.enum("image/jpeg", "image/png", "image/webp"),
      altText:  S.optional(S.string({ maxLength: 420 })),
    },
    ["cid", "mimeType"],
  ),
}
```

Blob bytes themselves live as separate content-addressed objects in the PDS. The body holds only the CID + metadata.

---

## 7. Cross-Major Migration

When you bump MAJOR, write a migrator. Migrators are pure functions:

```typescript
import type { KashEvent } from "@kashscript/lexicons";

export function migrateListing_v1_to_v2(v1: ListingBody_v1): ListingBody_v2 {
  return {
    title:      v1.title,
    priceCents: v1.priceMinor,        // rename
    currency:   "PKR",                // backfill default (this is your call as the lexicon owner)
  };
}

export function migrateEnvelope_v1_to_v2(env: KashEvent<ListingBody_v1>): KashEvent<ListingBody_v2> {
  return {
    header: { ...env.header, lexicon: "app.duedale.listing@2.0.0" as const },
    body:   migrateListing_v1_to_v2(env.body),
    // ⚠ signature is invalidated by body change — the migrated envelope is NOT a verifiable original.
    //   Treat migrated records as "presentation views"; preserve the original signed envelope for audit.
    signature: env.signature,
  };
}
```

**Important.** A migrated record's signature no longer covers its body. Migrators MUST NOT discard the original envelope — keep it alongside the migrated view so verifiers can always replay against the original.

---

## 8. Registry, Engine, and AI-Ingestion

### 8.1 The `LexiconRegistry`

The registry is **empty by default**. Consumers explicitly load what they need.

```typescript
import { LexiconRegistry } from "@kashscript/lexicons";
import { STANDARD_LIBRARY } from "@kashscript/lexicons";
import { SOCIAL_EXTENSION } from "@kashscript/lexicons/extensions/social";
import { TRADE_EXTENSION  } from "@kashscript/lexicons/extensions/trade";

const registry = new LexiconRegistry()
  .registerAll(STANDARD_LIBRARY)    // identity tier — kash.id.*
  .registerAll(SOCIAL_EXTENSION)    // opt-in   — kash.social.*
  .registerAll(TRADE_EXTENSION);    // opt-in   — kash.trade.*

// Register a single custom lexicon by ID + schema
registry.register("app.duedale.listing@1.0.0", LISTING_BODY_SCHEMA, {
  title: "Duedale Listing",
});

// Or register a fully-described LexiconDef
registry.register(LISTING_DEF);
```

Registry surface:

| Method                                | Returns                       | Purpose                                          |
|---------------------------------------|-------------------------------|--------------------------------------------------|
| `register(entry)` / `register(id, sch)` | `this`                      | Add a lexicon. Idempotent on (id) collision.     |
| `registerAll(entries)`                | `this`                        | Add a batch (typical for Standard Library / Extensions). |
| `get(id)`                             | `LexiconDef \| undefined`     | Exact-match lookup by full Lexicon ID.           |
| `resolve(nsid, semver)`               | `LexiconDef \| undefined`     | Forward-compatible lookup within major.          |
| `has(nsid)` / `hasId(id)`             | `boolean`                     | Existence checks.                                |
| `list()` / `entries()` / `namespaces()`| arrays                       | Introspection.                                   |
| `unregister(id)`                      | `boolean`                     | Drop a single entry.                             |
| `clear()`                             | `void`                        | Drop all entries.                                |
| `size`                                | `number`                      | Count of registered entries.                     |

### 8.2 The Engine — `validateEvent`

```typescript
import { validateEvent } from "@kashscript/lexicons";

const result = validateEvent<ListingBody>(envelopeFromPds, registry);
if (!result.ok) {
  for (const e of result.errors) {
    console.error(`${e.path.join(".")}: ${e.message}`);
  }
  return; // hard-reject
}

const env = result.value;   // KashEvent<ListingBody>
// env.body is now strongly typed as ListingBody
```

The engine runs a four-stage pipeline:

| Stage | Check                                                                       |
|-------|-----------------------------------------------------------------------------|
| 1     | Envelope shape — header types, signature shape, body permissive.            |
| 2     | Parse Lexicon ID from `header.lexicon`.                                     |
| 3     | Resolve in the registry — must support `(nsid, major)`.                     |
| 4     | Deep-validate `body` against the registered schema (recursive, all errors). |

`validateBody(lexiconId, body, registry)` is also available for validating a body before envelope construction.

### 8.3 AI-Ingestion Helper — `getSchemaDefinition`

Oreoasis and other AI/tooling consumers can fetch a JSON-Schema Draft-2020-12 representation of any registered lexicon at runtime:

```typescript
import { getSchemaDefinition } from "@kashscript/lexicons";

const schema = getSchemaDefinition("kash.id.profile@1.0.0", registry);
// →
// {
//   $schema:     "https://json-schema.org/draft/2020-12/schema",
//   $id:         "https://kashscript.com/lexicons/kash.id.profile@1.0.0",
//   title:       "Kash Profile",
//   description: "Sovereign user profile — display name, bio, avatar, pinned PDS URLs.",
//   type:        "object",
//   properties:  { displayName: { type: "string", minLength: 1, maxLength: 64 }, … },
//   required:    ["displayName"],
//   additionalProperties: false,
// }
```

This is what "teaches" an LLM (Oreoasis) a previously-unknown lexicon: the model receives the JSON-Schema, can validate prospective records against it, and can plan tool calls that produce well-formed bodies — **without any code change in the AI host**.

The internal-DSL representation is also available via `getRawSchema(id, registry)` for callers that prefer not to round-trip through JSON-Schema.

### 8.4 What the Engine Does NOT Check

- **Signature verification.** Requires public key + crypto runtime; handled by `@kashscript/signer` (Phase 3).
- **CID integrity.** Requires hashing the body bytes; handled by the storage / fetch layer.
- **Key authority.** Requires resolving the DID Document and checking `kid` against `authentication`; handled by `@kashscript/resolver` (Phase 3).
- **Freshness / replay.** Requires per-verifier state (used-nonce store); handled by the consuming app.

These are part of the **full Validation Protocol** in `identity-protocol-v1.md` §6 (PDS), which composes our schema layer with crypto + resolution layers.

---

## 9. Testing Your Lexicon

```typescript
import { describe, expect, test } from "bun:test";
import { LexiconValidator, S } from "@kashscript/lexicons";
import { LISTING_DEF } from "./listing";

const validator = new LexiconValidator([LISTING_DEF]);

test("valid listing passes", () => {
  const env = buildTestEnvelope("app.duedale.listing@1.0.0", {
    title: "Karachi rooftop apartment",
    description: "Two bedrooms, sea view.",
    priceMinor: 8_500_000,
    currency: "PKR",
    category: "rentals",
  });
  const result = validator.validate(env);
  expect(result.ok).toBe(true);
});

test("body missing required field", () => {
  const env = buildTestEnvelope("app.duedale.listing@1.0.0", {
    title: "Test",
    // priceMinor missing
    currency: "PKR",
    category: "goods",
  });
  const result = validator.validate(env);
  expect(result.ok).toBe(false);
  if (!result.ok) {
    expect(result.errors[0]?.path).toEqual(["body", "priceMinor"]);
    expect(result.errors[0]?.message).toMatch(/missing required/);
  }
});

test("future minor version still validates", () => {
  // 1.5.0 record against a v1.0.0-registered lexicon
  const env = buildTestEnvelope("app.duedale.listing@1.5.0", validListingBody);
  expect(validator.validate(env).ok).toBe(true);
});

test("cross-major version rejected", () => {
  const env = buildTestEnvelope("app.duedale.listing@2.0.0", validListingBody);
  const result = validator.validate(env);
  expect(result.ok).toBe(false);
});
```

### 9.1 Recommended Test Matrix

For each lexicon ship a `.test.ts` covering:

1. Round-trip — every required field present, every optional field present.
2. Each required field missing — should fail with a path-targeted error.
3. Each field violating its constraint (too long, wrong type, malformed format).
4. Unknown field rejected (unless `additionalProperties: true` is intended).
5. Forward-compat — a higher minor version validates.
6. Cross-major — rejected.

---

## 10. Publishing & Sharing

Lexicons are protocol-level artefacts. To share yours with the ecosystem:

1. **Publish** your `LexiconDef` from your app's package on npm/jsr.
2. **Document** the schema at a stable URL — e.g., `https://duedale.app/lexicons/listing-v1.html`.
3. **Mint a `kash.lexicon.definition` meta-record** in your own PDS so other apps can discover the schema via `did:kash` resolution (Phase-3 deliverable).
4. **Reserve your NSID** by being first-to-publish and documenting your namespace policy.

There is no central lexicon registry. Discovery is via:
- npm/jsr packages
- Documentation URLs
- `kash.lexicon.definition` meta-records in user PDSes
- DID-anchored handles

This mirrors the rest of the Kash protocol: headless, discoverable, no foundry-operated registry required.

---

## 11. Standard Library and Extensions

### 11.1 Standard Library — `kash.id.*`

Imported from the main package; included automatically when consumers call `registry.registerAll(STANDARD_LIBRARY)`. These three lexicons are what every Kash actor needs to interoperate at the identity layer.

#### `kash.id.profile@1.0.0`
Sovereign user profile. Single-record (`rkey: "self"`).
Required: `displayName` (1–64 chars). Optional: `handle`, `bio` (≤280), `avatar`, `banner`, `pronouns` (≤32), `location` (≤64), `pdsUrls[]` (max 8), `links[]` (max 8).

#### `kash.id.audit@1.0.0`
Append-only ledger of identity-state events.
Required: `event` (enum), `opCid`, `opSeq`, `opType`, `summary` (1–280). Optional: `details` (free-form record).
Event types: `key-rotated`, `key-revoked`, `pds-migrated`, `witnesses-changed`, `quorum-set`, `quorum-recovered`, `deactivated`.

#### `kash.id.preferences@1.0.0`
App-agnostic settings. Single-record. **Privacy-by-default**: all `allowAI.*` flags default to FALSE.
Optional: `language` (BCP 47), `theme`, `privacy.{profileVisibility,indexable,allowAI?}`, `notifications.*`, `units.*`.
**Oreoasis ingest gate:** Oreoasis MUST verify `allowAI.neuronIngest === true` before ingesting any record from a DID. Absence is denial.

### 11.2 Social Extension — `kash.social.*`

```ts
import { SOCIAL_EXTENSION } from "@kashscript/lexicons/extensions/social";
```

| Lexicon                              | Purpose                                                            |
|--------------------------------------|--------------------------------------------------------------------|
| `kash.social.post@1.0.0`             | A post — text, media, optional Bento-style tile metadata.          |
| `kash.social.interaction@1.0.0`      | Unified like / share / react event against a post.                 |
| `kash.social.follow@1.0.0`           | Directed follow relationship between two DIDs.                     |

### 11.3 Trade Extension — `kash.trade.*`

```ts
import { TRADE_EXTENSION } from "@kashscript/lexicons/extensions/trade";
```

| Lexicon                              | Purpose                                                            |
|--------------------------------------|--------------------------------------------------------------------|
| `kash.trade.offer@1.0.0`             | An item or service for sale — ISO 4217 price, optional location.   |
| `kash.trade.receipt@1.0.0`           | Cryptographically signed completed transaction (dual-receipt).     |
| `kash.trade.status@1.0.0`            | Lightweight logistics update bound to a receipt.                   |

### 11.4 Cross-Domain Interop

The single load-bearing interop point is the optional `linkedPost` field on `kash.trade.receipt`:

```jsonc
{ "header": { "lexicon": "kash.trade.receipt@1.0.0" },
  "body": {
    "offer":        { "cid": "bafy…", "uri": "at://did:kash:…/kash.trade.offer/…" },
    "counterparty": "did:kash:bbb…",
    "role":         "buyer",
    "price":        { "amount": "8500.00", "currency": "PKR" },
    "settledAt":    "2026-05-11T09:00:00Z",
    "linkedPost":   { "cid": "bafy…", "uri": "at://did:kash:aaa…/kash.social.post/…" }
  } }
```

Receipts reference the originating social post by CID + URI. No coupling at the package layer — Trade Extension contains its own ref shape; nothing forces Social and Trade to be co-loaded. An installation that only handles trade still validates receipts; the `linkedPost` ref is opaque from its perspective.

### 11.5 Bootstrap: Agnostic Core Only

To ship a pure-identity product (no domain content):

```ts
import { LexiconRegistry, validateEvent, STANDARD_LIBRARY } from "@kashscript/lexicons";

const registry = new LexiconRegistry().registerAll(STANDARD_LIBRARY);

// registry.size === 3 (only the three identity lexicons)
// registry.namespaces() === ["kash.id.profile", "kash.id.audit", "kash.id.preferences"]
```

That's the entire agnostic-core surface. No social, no trade, no app-specific schemas — but every record under `kash.id.*` validates end-to-end.

---

## 12. File Structure for `@kashscript/lexicons`

```
packages/lexicons/
├── package.json
├── tsconfig.json
└── src/
    ├── index.ts                       # main surface — Box + Standard Library
    ├── types.ts                       # DID, CID, LexiconId, KASH_RECORD_DST
    ├── schema.ts                      # Schema variants + S DSL + validator engine
    ├── semver.ts                      # parseLexiconId, isForwardCompatible
    ├── envelope.ts                    # KashEvent, KashHeader, KashSignature + schemas
    ├── registry.ts                    # LexiconRegistry class + LexiconDef
    ├── engine.ts                      # validateEvent, validateBody, getSchemaDefinition
    ├── json-schema.ts                 # toJsonSchema converter (Schema → JSON-Schema 2020-12)
    ├── lexicons/                      # STANDARD LIBRARY — identity tier only
    │   ├── index.ts                   #   exports STANDARD_LIBRARY
    │   ├── kash-id-profile.ts
    │   ├── kash-id-audit.ts
    │   └── kash-id-preferences.ts
    └── extensions/                    # OPT-IN content
        ├── social.ts                  #   exports SOCIAL_EXTENSION
        └── trade.ts                   #   exports TRADE_EXTENSION
```

**Package exports** (from `package.json`):

| Specifier                                  | Surface                                              |
|--------------------------------------------|------------------------------------------------------|
| `@kashscript/lexicons`                     | Box + Standard Library (everything except extensions)|
| `@kashscript/lexicons/envelope`            | Envelope types and schemas only                      |
| `@kashscript/lexicons/schema`              | Schema DSL only                                      |
| `@kashscript/lexicons/registry`            | LexiconRegistry + LexiconDef                         |
| `@kashscript/lexicons/engine`              | validateEvent, validateBody, getSchemaDefinition     |
| `@kashscript/lexicons/json-schema`         | toJsonSchema converter only                          |
| `@kashscript/lexicons/semver`              | parseLexiconId, isForwardCompatible                  |
| `@kashscript/lexicons/extensions/social`   | SOCIAL_EXTENSION + types                             |
| `@kashscript/lexicons/extensions/trade`    | TRADE_EXTENSION + types                              |

**Typical imports:**

```typescript
// framework + standard library (everything from the main entry)
import {
  LexiconRegistry, validateEvent, getSchemaDefinition,
  STANDARD_LIBRARY,
  S, type Schema, type KashEvent, type LexiconDef,
} from "@kashscript/lexicons";

// opt-in domain content
import { SOCIAL_EXTENSION } from "@kashscript/lexicons/extensions/social";
import { TRADE_EXTENSION  } from "@kashscript/lexicons/extensions/trade";
```

---

## 13. Building Third-Party Extensions

> **This section is what an external developer reads.** Build an extension when your app introduces records that other Kash actors should be able to read, validate, or index. Skip this if your data is purely app-internal — those go through plain code, not the lexicon framework.

### 13.1 What an Extension Is

An extension is a **standalone package** that:

1. Exports one or more `LexiconDef`s under your `app.<your-name>.*` NSID namespace.
2. Exports an `<APP>_EXTENSION` array consumers register at bootstrap.
3. Optionally exports the body types and schemas for typed consumption.
4. Has `@kashscript/lexicons` as the **only** runtime dependency.

Naming convention: `@<org>/<app>-lexicons`. Examples: `@duedale/duedale-lexicons`, `@indusland/indusland-lexicons`.

### 13.2 Skeleton

```typescript
// packages/myapp-lexicons/src/index.ts
import { S, type ObjectSchema } from "@kashscript/lexicons/schema";
import type { LexiconDef } from "@kashscript/lexicons/registry";

export const MYAPP_THING_NSID    = "app.myapp.thing" as const;
export const MYAPP_THING_VERSION = { major: 1, minor: 0, patch: 0 } as const;
export const MYAPP_THING_ID      = "app.myapp.thing@1.0.0" as const;

export interface MyAppThingBody {
  readonly title: string;
  readonly count: number;
}

export const MYAPP_THING_BODY_SCHEMA: ObjectSchema = S.object(
  {
    title: S.string({ minLength: 1, maxLength: 140 }),
    count: S.number({ integer: true, min: 0 }),
  },
  ["title", "count"],
);

export const MYAPP_EXTENSION: readonly LexiconDef[] = [
  {
    id:          MYAPP_THING_ID,
    nsid:        MYAPP_THING_NSID,
    semver:      MYAPP_THING_VERSION,
    bodySchema:  MYAPP_THING_BODY_SCHEMA,
    title:       "MyApp Thing",
    description: "What a thing in MyApp looks like.",
  },
];
```

### 13.3 Consumer Bootstrap

Anyone consuming your extension does this once at startup:

```typescript
import { LexiconRegistry, STANDARD_LIBRARY } from "@kashscript/lexicons";
import { MYAPP_EXTENSION } from "@myapp/myapp-lexicons";

const registry = new LexiconRegistry()
  .registerAll(STANDARD_LIBRARY)
  .registerAll(MYAPP_EXTENSION);
```

That's it. The registry now validates `app.myapp.*` records alongside identity-tier records, with no foundry coordination, no central registry, and no code changes inside the Box.

### 13.4 Rules an Extension MUST Follow

1. **Stay inside your NSID root.** Use `app.<your-name>.*`. Do not register schemas under `kash.*` — those are protocol-reserved.
2. **Pure data.** Schema files have zero side effects. No I/O on import.
3. **Zero non-`@kashscript/lexicons` runtime dependencies.** Anything else makes you un-bundleable.
4. **Semver discipline.** PATCH = docs; MINOR = additive optional; MAJOR = breaking. See §3.
5. **Provide a migrator** for every MAJOR bump. Ship it from the same package.
6. **Match the Box's `ObjectSchema` strictness** — set `additionalProperties: false` on records you own, unless you have a deliberate reason otherwise.
7. **Document the consent gate** if your records touch personal data — Oreoasis honours `kash.id.preferences.allowAI.*` automatically, but third-party AI tools rely on you flagging what fields are sensitive.

### 13.5 Discovery & Distribution

There is no central registry. Discoverability mechanisms:

- **npm / jsr packages** — `npm install @myapp/myapp-lexicons`.
- **Documentation URLs** — host the schema at a stable URL under your domain.
- **`kash.lexicon.definition` meta-records in user PDSes** — Phase-3 deliverable; lets resolvers fetch a schema by DID + Lexicon ID.
- **Foundry signer / app registries** — apps may surface known extensions to users on first encounter.

### 13.6 Selling Your Extension

The Box itself is sellable: a customer can pay for a hosted PDS / signer / resolver stack and bring their own extensions. The agnostic-core boundary means you (the extension author) control your domain content, distribute it however you want, and the foundry never sees the bytes inside a body it has not been asked to validate.

The contract with the framework is: **your extension lives outside the package boundary, and the Box honours it exactly as it honours its own Standard Library.**

---

## 14. Anti-Patterns to Avoid

| Anti-pattern                                                  | Why it's bad                                                  | Do this instead                                  |
|---------------------------------------------------------------|---------------------------------------------------------------|--------------------------------------------------|
| Free-form `Record<string, any>` body                          | No validation, no forward-compat reasoning.                   | Enumerate fields; use `S.union` for variants.    |
| Tightening a constraint as MINOR                              | Invalidates existing records silently.                        | Bump MAJOR; ship migrator.                       |
| Re-using an existing NSID for a different concept             | Verifiers can't disambiguate.                                 | Mint a new NSID.                                 |
| Storing personal data unencrypted in a body                   | Records may leak via federation / public collection access.   | Encrypt client-side; store ciphertext + key wrap.|
| Embedding huge blobs in the body (>1 MB)                      | JCS serialisation, CID computation, replay all become slow.   | Store blob separately; reference by CID.         |
| Signing a record with a Management or Recovery key            | Tier-confusion attack surface; verifier hard-rejects.         | Always sign records with a `purpose: "active"` key. |
| Picking your own DST                                          | Fragments the security domain; no central tag registry.       | Use the fixed `kash-record-v1\n`.                |

---

## Change Log

| Version | Date       | Summary                                                                                |
|---------|------------|----------------------------------------------------------------------------------------|
| **v1.0** | 2026-05-11 | **Initial release** of the developer guide alongside the `@kashscript/lexicons` package. Covers NSID + semver, envelope, DSL, registration, common patterns, cross-major migration, testing, file structure, and anti-patterns. |
| **v1.1** | 2026-05-11 | **Box-vs-Content refactor.** Split `LexiconValidator` into `LexiconRegistry` (storage) + `validateEvent` (pure function). Moved Social and Trade out of the Standard Library into opt-in extensions under `@kashscript/lexicons/extensions/*`. Added `getSchemaDefinition` for runtime JSON-Schema export (Oreoasis ingestion). New §0.1 Box-vs-Content separation. New §13 Building Third-Party Extensions (for external customers). §8 rewritten around registry + engine. Standard Library renamed from `BASE_LEXICONS` → `STANDARD_LIBRARY`; domain bundles renamed from `*_LEXICONS` → `*_EXTENSION`. |
| **v1.2** | 2026-07-04 | **Terminology unification (ROADMAP P0).** DID method label unified to `did:kash` throughout, matching the shipped `@kashscript/identity-core` runtime (which enforces `did:kash` and rejects the retired spelling). Prose/label change only; no schema or protocol-semantic change. |

> Phase-3 implementations (`@kashscript/signer`, `@kashscript/resolver`, `@kashscript/pds-client`) MUST consume `@kashscript/lexicons` as their schema and validation layer. Do not duplicate the DSL.
