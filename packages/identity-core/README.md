# @kashscript/identity-core

> **Zero-dependency cryptographic primitives + `did:kash` DID Document formatter + Kash-Event sign/verify.**

Pure deterministic logic — no network calls, no storage, no platform APIs.
Runs in Node 20+, Bun, Deno, browsers, edge runtimes, and Web Workers.

```bash
bun add @kashscript/identity-core
# or
npm install @kashscript/identity-core
```

---

## What's in the box

| Subpath                            | Purpose                                           |
|------------------------------------|---------------------------------------------------|
| `@kashscript/identity-core`        | Default export — re-exports everything below      |
| `@kashscript/identity-core/keys`   | Ed25519 keypair generation + serialization        |
| `@kashscript/identity-core/p256`   | P-256 / ES256: points, low-S signing and verifying, strict DER (PL-2) |
| `@kashscript/identity-core/runtime` | What this runtime's WebCrypto can run — `ALG_UNAVAILABLE`, never "invalid" |
| `@kashscript/identity-core/did`    | `did:kash` for Ed25519 (`<base58btc key>`) and P-256 (`Dn…`, multicodec `p256-pub`); `parseDidKey` returns the key with the type its DID declares |
| `@kashscript/identity-core/document` | W3C-compatible DID Document builder             |
| `@kashscript/identity-core/canonical` | RFC 8785 JSON Canonicalization (JCS)           |
| `@kashscript/identity-core/signatures` | Detached signatures over JCS bytes            |
| `@kashscript/identity-core/signer` | High-level `Signer` — keypair + DID + sign/verify |
| `@kashscript/identity-core/base58` | base58btc encode/decode (no deps)                 |
| `@kashscript/identity-core/base64url` | base64url encode/decode                        |
| `@kashscript/identity-core/hex`    | hex encode/decode                                 |
| `@kashscript/identity-core/errors` | `KashCryptoError` + stable `KashCryptoErrorCode`  |
| `@kashscript/identity-core/types`  | DID/document types + resolver/registrar/PDS SPIs  |
| `@kashscript/identity-core/license` | Runtime license-token verifier (subpath only)    |

---

## Quickstart

```typescript
import { Signer } from "@kashscript/identity-core/signer";

// Generate a fresh identity — no registrar, no chain, no fee.
const signer = await Signer.generate();
console.log(signer.did);                          // did:kash:z6Mk...

// Sign a Kash-Event: sign(header, body). `kid` defaults to `${signer.did}#sig-1`.
const header = { did: signer.did, lexicon: "kash.app.note@1.0.0", iat: new Date().toISOString() };
const body = { msg: "hello", n: 42 };
const signature = await signer.sign(header, body);
const event = { header, body, signature };

// Verify on the other side (instance method, takes the whole event).
const ok = await signer.verify(event);            // true
```

The DID is derived deterministically from the public key — no registrar, no
chain, no fee. The signature is computed over the **RFC 8785 canonical JSON**
of `{ header, body }` (with a domain-separation tag), so two semantically-equal
events always produce the same signature target.

---

## Why a separate `identity-core`?

The Kash Identity Platform is split so that the **trust-free** core (this
package) can be embedded anywhere — including environments where Web APIs,
storage, or networking would be unsafe or unavailable. Higher layers
(`@kashscript/identity-sdk`, `@kashscript/identity-zkp`) bring in WebAuthn,
storage, ZK primitives.

- **No `window`, no `localStorage`, no `fetch` here.**
- **No third-party dependencies.** Audited line-by-line.
- **Deterministic.** Same inputs → same outputs, every time.

---

## Changelog

| Version | Date | Change |
|---|---|---|
| **0.4.0-alpha.2** | 2026-11-13 | **A Buffer handed in is read, never written (found during AU-3b).** On a Node Buffer `.slice()` is a view of the caller's memory, not a copy: `ed25519-strict` "copied" a key that way and cleared bit 255 of it, so every later check under a key with that bit set failed (Oreoasis refused agent tokens for those organisations). The same pattern rewrote a high-S signature in place in `normaliseLowS`, and handed WebCrypto a pooled Buffer's whole pool in the licence check. All three now copy with `new Uint8Array(…)`. Test: `src/buffer-input.test.ts`, keys and signatures as Buffer views at an offset. **78 tests green.** **Published by hand under `alpha` on 2026-11-13, without provenance (d97(n)); `latest` moved to it the same day.** attest `0.2.0-alpha.10` and predicate `0.3.0-alpha.2` pin it (published and made `latest` the same day); the earlier attest `0.2.0-alpha.9` and predicate `0.3.0-alpha.1` pin `0.4.0-alpha.1`. |
| **0.4.0-alpha.1** | 2026-11-12 | **The Ed25519 acceptance rule, pinned (AU-3, A7-07; AUDIT-2026-11-11).** `./ed25519-strict`: before WebCrypto is asked, `S < L`, `A` and `R` decoded strictly (canonical `y`, on the curve, no sign bit on `x = 0`), and neither `A` nor `R` of small order — libsodium's rule, so a signature of zeros under the identity key no longer verifies every message on BoringSSL. `verifyEvent` / `verifyEventForKey` apply it; attest's raw layer applies the same one. Exposes `ed25519Precheck`, `decodeEd25519Point`, `encodeEd25519Point`, `addEd25519Points`, `isSmallOrderEd25519Point`, `isCanonicalEd25519Scalar`, `ED25519_ORDER_L`. Vectors and the pinned verdicts: `attest/test/vectors/ed25519` (Wycheproof, ed25519-speccheck, attest's own), asserted under bun, node and Chromium. Every honest signature is unchanged. **Published by hand under `alpha` on 2026-11-12, without provenance (d97(n)).** Superseded by 0.4.0-alpha.2: on a Node Buffer key it clears the caller's bit 255. |
| **0.4.0-alpha.0** | 2026-10-01 | **P-256 beside Ed25519 (PL-2, ADR-0020).** A P-256 `did:kash` — `did:kash:Dn…`, multicodec `p256-pub` and the compressed point, the bytes `did:key` carries — read through `parseDidKey` / `didKeyType` / `deriveDidP256` / `deriveDidForKey`; `parseDid`, `deriveDid` and `isKashDid` keep their exact Ed25519 meaning, so every older path fails closed on a P-256 identifier. The reserved `es256` signature slot is implemented: raw `r ‖ s`, low-S on signing, high-S rejected on verifying; `signEventWith` takes a hardware signer; `verifyEventForKey` takes the algorithm from the key. DID documents carry a P-256 `Multikey`. `./p256` (points, signing, strict DER) and `./runtime` (`ALG_UNAVAILABLE` — not checked, never invalid). Every Ed25519 identifier is unchanged (RFC 8032's test key keeps its DID). **63 tests green.** **Prerelease, not published** — founder-terminal. |
| 0.3.1 | — | The published version members pin (STACK verified it `[v 07-27]`); earlier history is in git. |

## License

Apache-2.0. Also covered by SSLA v1.0 Schedule A (Permissive). See [LICENSE](./LICENSE).
