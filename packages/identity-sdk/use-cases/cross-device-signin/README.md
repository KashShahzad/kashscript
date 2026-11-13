# Use case · Cross-device sign-in

> **Status:** runnable · 12/12 tests passing (first run) · 1 artifact gap surfaced (workaround in fixture).

Use case #2 in the Identity maturity sprint. Alice provisions her account on Device A (laptop). She wants the same account on Device B (phone). The two devices share her identity by transferring an export bundle — in the real world via iCloud Keychain, Google Password Manager, or a WebAuthn cross-device flow. After the transfer, both devices can publish records signed by the same DID.

The use case exercises the **portability primitive** that everything else builds on: `Signer.exportJwk()` ↔ `Signer.fromJwk()` is byte-stable. The DID survives device change because the DID is just a function of the public key.

---

## What this proves

| Property | How |
|---|---|
| **JWK round-trip is byte-stable** | `Signer.fromJwk(s.exportJwk()).did === s.did` — and the rebuilt Signer's public key bytes match the original's. |
| **Storage envelope round-trips** | `HeadlessIdentityStorage` write → exportBundle → importBundle → read returns identical data. |
| **Same DID, multiple devices** | Device A provisions; Device B adopts A's bundle; both have identical DID + pubkey. |
| **Both devices publish under one DID** | Records from both devices land in the same `(did, lexicon)` collection on Muffler. |
| **Sovereignty preserved** | A device that never adopted Alice's bundle cannot publish under her DID. Its DID is different by construction. |
| **Sign-out is destructive (on that device)** | After `signOut()`, the device has no identity in storage; `hydrate()` correctly throws. The other device's state is unaffected. |

---

## Files

```
cross-device-signin/
├── README.md             ← this file
├── flow.md               ← user-flow + cross-device data-flow
├── io.md                 ← Device + HeadlessIdentityStorage I/O contracts
├── policies.md           ← what "same identity" means; transfer security
├── errors.md             ← GAP-004 + the runtime errors a consumer sees
└── fixture/
    ├── headless-storage.ts    — Node/Bun storage adapter (GAP-004 workaround)
    ├── device.ts              — one device's worth of state + ops
    └── integration.test.ts    — 12 tests across 3 describe blocks
```

Run with:
```bash
cd packages/identity-sdk
bun test use-cases/cross-device-signin
# or both use cases at once:
bun test use-cases
```

Shared fixtures (`MufflerHost`, `InduslandConsumer`, `signature-bridge`) are imported from `../muffler-ingest/fixture/` — no duplication.

---

## The gap this surfaced

### GAP-004 · `identity-sdk/storage` is browser-only

The published `@kashscript/identity-sdk/storage` module is hard-wired to `window.localStorage` + `IndexedDB`. There's no:
- interface or pluggable adapter pattern
- headless (Node/Bun) implementation
- file-backed implementation for CLI usage

Any consumer running outside a browser — a Bun script, a Node service, the `kash` binary in headless mode — cannot use the ship-with storage at all. They roll their own, every single time.

**Workaround applied:** `fixture/headless-storage.ts` is the in-memory adapter every headless consumer ends up writing. It speaks the same `KashIdentity` + `StoredKashIdentity` shapes from `identity-sdk/types` so a future `identity-sdk/storage-headless` or `/storage-file` subpath could lift it directly.

**Upstream fix (recommended):**
1. Define an `IdentityStorageAdapter` interface in `identity-sdk/storage` with `read / write / clear / exportBundle / importBundle` methods.
2. Refactor the existing browser code to implement that interface as `BrowserIdentityStorage`.
3. Add a sibling `HeadlessIdentityStorage` (in-memory) for tests + scripts.
4. Optionally add `FileIdentityStorage` (for the CLI's `~/.kash/credentials.json` use case — currently each consumer reimplements).

**Status:** workaround applied; upstream fix is open work.

---

## What this didn't prove

- **WebAuthn cross-device flow** (QR-code + companion phone) — that's a browser interaction, not testable in Bun. The use case substitutes JWK export/import via in-memory transfer; the cryptographic story is the same (same key → same DID), only the UX differs.
- **Native key-sync** (iCloud Keychain, Google Password Manager) — these are platform APIs the SDK doesn't touch; their integration is the OS's responsibility, not KashScript's.
- **Bundle transfer security** (how do you safely move a JWK between devices?) — addressed in `policies.md` as out-of-scope cryptographic concern. The fixture transfers the bundle in-memory.
- **Conflict resolution when both devices publish to the same rkey** — covered by `RKEY_DUPLICATE` from use case 1. Cross-device doesn't add a new conflict surface.

---

## What's next

This was the second flagship. After this:

- **Trade flagship** (Whiffin POS tap-to-pay) — exercises `trade-sdk/core` + paymaster + EIP-712 signal layer. Estimated 1-2 days.
- **Neuron flagship** (Chakor refund agent) — exercises `neuron/kernel` + restricted scopes + receipt chain. Estimated 1-2 days.

Or, in parallel: **close GAP-001, GAP-002, GAP-004 upstream** (estimated half a day total) before adding a third use case. That gives all subsequent use cases a cleaner starting position.
