# Ed25519 edge cases — one verdict, pinned (AU-3, A7-07)

Ed25519 engines agree on honest signatures and disagree at the edges: BoringSSL (Bun, Chromium) accepts a public key or an `R` of small order and one non-canonical key encoding that libsodium refuses; OpenSSL (Node) differs case by case. The same record is checked by Bun, Node and three browsers, so the acceptance rule is fixed in `identity-core/src/ed25519-strict.ts` and applied before WebCrypto is asked:

1. `S < L` (RFC 8032 §5.1.7) — a non-canonical `S` is refused, never reduced;
2. `A` and `R` decode strictly — `y < p`, a point on the curve, and no sign bit on `x = 0`;
3. neither `A` nor `R` has small order (`8·P = O`) — libsodium's rule;
4. then WebCrypto's cofactorless equation, `[S]B = R + [k]A`, decides.

`expected.v1.json` carries one verdict per case; `test/ed25519-vectors.test.ts` asserts it under bun and under plain node (a bundle built by `bun build --target node`), and `test/browser-smoke.test.ts` under headless Chromium.

| File | Source | Cases | Verdict rule |
|---|---|---|---|
| `wycheproof-ed25519_test.json` | [C2SP/wycheproof](https://github.com/C2SP/wycheproof) `testvectors_v1/ed25519_test.json`, copied unchanged (Apache-2.0, `LICENSE.wycheproof`) | 210 | `valid` → verifies · `invalid` → does not · `acceptable` → verifies only for a key of mixed order (`MixedOrderPublicKey`), not of small order (`SmallOrderPublicKey`) |
| `speccheck-cases.json` | [novifinancial/ed25519-speccheck](https://github.com/novifinancial/ed25519-speccheck) `cases.json`, copied unchanged (Apache-2.0, `LICENSE.speccheck`; the paper is *Taming the many EdDSAs*, Chalkias, Garillot, Nikolaenko, SSR 2020) | 12 | only case 3 verifies: cases 0–2 have a small-order `A` or `R`, 4–5 fail the cofactorless equation, 6–7 have `S ≥ L`, 8–11 a non-canonical `R` or `A` |
| `generated.v1.json` | attest's own, by `gen-ed25519-vectors.ts` on 2026-11-12 (a fresh key, thrown away; never regenerate) | 28 | one honest signature verifies; `S + L`, `S = L`, a canonical but wrong `S`, non-canonical and off-curve `R` and `A`, and `R` or `A` at each of the eight small-order points do not — each with the pre-check's reason recorded |

`webcryptoAlone` in `generated.v1.json` is what one engine (Bun's BoringSSL) said with no pre-check, for the record: it accepted `a-small-order-0-zero-signature` — a signature of zeros under the identity key, which would verify every message. The rule refuses it everywhere.
