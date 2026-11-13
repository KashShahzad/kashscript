# Use case · Muffler ingests a signed `kash.social.post`

> **Status:** runnable · 14/14 tests passing · 3 artifact gaps surfaced + closed during build.

The flagship Identity use case. A user composes a social post in an Indusland client app; the app signs the post against the user's `did:kash:` keypair; the post is submitted to a Muffler PDS/DWN host; the host verifies the envelope shape, the lexicon body schema, the cryptographic signature, and the DID-to-pubkey coherence — then stores it. The whole thing is exercised end-to-end against the **live** `@kashscript/identity-core`, `@kashscript/identity-sdk`, and `@kashscript/lexicons` packages.

This isn't a smoke test. It's the contract Indusland would need against Muffler for v1 to ship.

---

## What this proves

| Property | How |
|---|---|
| **Identity sovereignty** | The same `Signer` publishes to two independent hosts without re-registering anywhere. The DID survives host change. |
| **Author authenticity** | Every accepted record carries an Ed25519 signature derivable from the DID — no host trust required. |
| **Tamper detection** | Mutating the body after signing surfaces as `SIGNATURE_INVALID`; mutating the DID surfaces as `DID_MISMATCH` / `DID_DERIVE_FAILED`. |
| **Schema enforcement** | A post that violates the `kash.social.post@1.0.0` body schema (e.g., text > 1000 chars) is rejected with `LEXICON_VALIDATION_FAILED` before signature verification even runs. |
| **DST isolation** | A signature minted under `kash-record-v1\n` cannot be reused as, say, a trade-tier signature. Host policy can demand a specific DST. |
| **Idempotency boundary** | Same `rkey` in the same `(did, lexicon)` collection rejects as `RKEY_DUPLICATE`. |

---

## Files

```
muffler-ingest/
├── README.md             ← this file (the narrative)
├── flow.md               ← user-flow + data-flow diagrams
├── io.md                 ← per-method I/O contracts
├── policies.md           ← operational rules the host enforces
├── errors.md             ← every typed error + the 3 artifact gaps found
└── fixture/
    ├── muffler-stub.ts        — in-process PDS/DWN host (verifies + stores)
    ├── consumer.ts            — Indusland-app side (signs + posts)
    ├── signature-bridge.ts    — identity-core ↔ lexicons signature-shape bridge
    └── integration.test.ts    — Bun test, 14 cases across 3 describe blocks
```

Run with:
```bash
cd packages/identity-sdk
bun test use-cases
```

---

## The three gaps the use case surfaced (and fixed)

Every one of these was a real wire-format inconsistency between packages that ship together. The use case was the first thing to actually exercise them end-to-end.

### GAP-001 · Signature shape disagreement

`@kashscript/identity-core/signer` emits `KashEventSignature` with:
- `sig`: base64url-encoded bytes
- `encoding`: `"base64url" | "hex"` (a field telling consumers how to decode)
- `kid?`: optional

`@kashscript/lexicons/envelope` expects `KashSignature` with:
- `sig`: multibase-encoded bytes (z-prefix base58btc)
- `dst`: literal `kash-record-v1\n`
- `kid`: REQUIRED
- No `encoding` field

**Resolution applied:** `signature-bridge.ts` converts in both directions. Consumer side: identity-core shape → lexicons shape (base64url → bytes → multibase). Host side: lexicons shape → identity-core shape (multibase → bytes → base64url) before calling `verifyEvent`.

**Suggested upstream fix:** add `encoding: "multibase"` as a `SignEventOptions` value in identity-core. Have `verifyEvent` accept either shape. Then the bridge becomes a one-time-only adapter, deletable.

### GAP-002 · `identity-core` doesn't export `./base64url`

`identity-core` ships `src/base64url.ts` with `encodeBase64Url` / `decodeBase64Url`. Its root `index.ts` re-exports them. But its `package.json` `exports` map doesn't include `./base64url`, so consumers can't deep-import without using the bigger root.

**Resolution applied:** the bridge imports `{ encodeBase64Url, decodeBase64Url }` from the root `@kashscript/identity-core`. Bundle-size cost is ignorable (Bun/Vite/Next tree-shake), but the deep-import API is misleading.

**Suggested upstream fix:** add `"./base64url": "./src/base64url.ts"` to `identity-core/package.json` exports.

### GAP-003 · Two different DID method conventions

`identity-core` produces `did:kash:<base58btc-pubkey>` (variable length, 43-44 chars for Ed25519).

`@kashscript/lexicons` validates DIDs against format `did-ks` whose regex was `/^did:kash:[a-z2-7]{32}$/` — base32-lowercase, exactly 32 chars, **different DID method name**.

Same project, two competing conventions. Any record signed by identity-core would have been rejected by the lexicons engine before the maturity sprint.

**Resolution applied (in-place fix to lexicons):**
- `schema.ts:162` — the `did-ks` format regex now reads `/^did:kash:[1-9A-HJ-NP-Za-km-z]{32,48}$/` (matches what identity-core emits)
- `types.ts:8` — `type DID` brand changed from `` `did:kash:${string}` `` to `` `did:kash:${string}` ``
- `envelope.ts:26` — example comment updated
- `envelope.ts:120` — `AT_URI_PATTERN` updated to match the new DID format

The schema-internal format-id (`did-ks`) was kept for backward compatibility — it's an opaque name only used by the schema engine.

---

## What's NOT in scope for this use case

These are real Muffler product behaviours but out of scope here (covered by follow-up use cases):

- **Federation / replication** — Muffler ingests, but doesn't yet replicate to follower hosts. Phase 2.
- **Indexing for discovery** — every record has an `rkey` but no inverted index for tag/text search.
- **Revocation** — the host has no `revoke(did, lexicon, rkey)` API yet.
- **Cross-host migration** — the test proves the *Signer* survives host change, but doesn't migrate the *record set*. A real migration tool would walk the old host, re-sign nothing (DIDs are stable), and bulk-ingest to the new host.
- **Browser WebAuthn flow** — this use case uses `Signer.generate()` (in-memory key); a real Indusland client would Passkey-bind via `identity-sdk/webauthn`. Headless equivalence is what we're testing here.

---

## Next use cases (after this one)

1. **Cross-device sign-in** — same DID, two devices, both can sign records. Tests `identity-sdk/webauthn` + storage adapters.
2. **Selective disclosure via Merkle** — present a credential field without exposing the full DID Document. Tests `identity-zkp/disclosure`.
3. **Trade flagship: Whiffin POS tap-to-pay** — buyer + seller co-sign an OTDC. Tests `trade-sdk/core` + paymaster.
4. **Neuron flagship: Chakor refund agent** — agent loads SOP, dispatches refund tool, returns signed receipt. Tests `neuron/kernel` + restricted scopes.

Each follows the same six-file shape (README + flow + io + policies + errors + fixture). The template is locked here.
