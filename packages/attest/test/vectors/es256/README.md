# ES256, cross-algorithm succession and helper-quorum recovery — conformance vectors (PL-2)

Generated once by `gen-es256-vectors.ts` on 2026-10-01 and **never regenerated**. Every key except the RFC 6979 one is fresh, and ECDSA signatures are randomised, so a second run would change every byte. Everything here is a simulation (ECOSYSTEM d11): no real person, place or organisation, and only attest's own formats are sampled. The P-256 keys are inside their `did:kash` identifiers (`did:kash:Dn…`, ADR-0020), so nothing is needed to check them but the files.

| File | What it is |
|---|---|
| `did-p256.v1.json` | RFC 6979 §A.2.5's P-256 test key: its compressed point, its `did:kash`, and its DID document (Multikey `zDn…`). **Its private scalar is published in the RFC — never use it for anything real.** |
| `kash-event-es256.v1.json` | A Kash-Event signed `es256` by that key: raw `r ‖ s`, low-S, multibase. |
| `trust-list-es256.v1.json` | A `kashscript-trust-list/1` whose publisher is a P-256 `did:kash` — a DSSE envelope with a strict-DER ES256 signature. |
| `status-list-es256.v1.json` | A 131,072-entry status list signed ES256 by a P-256 issuer; index 70411 revoked, index 3209 clear. |
| `predicate-held-es256.v1.txt` | A predicate credential (SD-JWT VC) issued ES256 by that issuer, bound to a P-256 holder key (`cnf.jwk` is an EC key). |
| `predicate-presentation-es256.v1.txt` | Its presentation with an **ES256 KB-JWT**. Audience, nonce and the time to check at are in `context.v1.json`. |
| `countersign-es256.v1.json` | A countersign bundle: an Ed25519 requester's subject, countersigned by a **P-256** key (DER on the envelope, `es256` on the acceptance), carrying two prior-key claims — **Ed25519 → P-256** and **P-256 → Ed25519**. |
| `succession-helpers.v1.json` | Recovery: an Ed25519 relationship key on a lost phone named three helper keys (one P-256, two Ed25519) in advance; **two of them and its new P-256 key** moved its authority. |
| `holder-export-es256.v1.json` | A `kashscript-holder-export/1` (canonical bytes) carrying an ES256 Kash-Event record, the ES256 predicate, the ES256 trust and status lists, both kinds of claim, and the new key's own helper set in `recoveryHelpers` (holder contract v1.3). |
| `negative.v1.json` | Cases that must **fail**: a high-S Kash-Event, a high-S DSSE, a non-minimal DER, a high-S KB-JWT, an Ed25519 signature under a P-256 `did:kash` and the reverse, a 1-of-3 helper claim, a helper set not signed by its key, and a fork (two successors; one helper signed both). |

```
attest verify holder-export-es256.v1.json --trust-publisher <context.v1.json trustPublisher>
attest verify countersign-es256.v1.json
```

Expected: `RESULT: PASS`, `network: none`. Every vector passes under Node 22 and in a browser build (headless Chromium) — see `test/bin-node-smoke.test.ts` and `test/browser-smoke.test.ts`.
