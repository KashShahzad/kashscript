# KS-Q4 vectors — the trust log

Generated once by `gen-log-vectors.ts` on 2026-11-18 and **never regenerated**. The generator made three sets of keys and discarded them: the log's key, a stranger's key, and the keys of a SAMPLE time authority. Everything here is a simulation (ECOSYSTEM d11).

**The witnesses are real RFC 3161 tokens from a SAMPLE authority.** The generator created a root and a time-stamping certificate under it with openssl, and had `openssl ts -reply` stamp each checkpoint's payload hash. Only the root's certificate is kept, as `sample-tsa-root.crt`, so openssl, and attest through `--tsa-root`, check every token against it. **The tokens show the generator's clock and nothing more.** No public authority saw any of this, and the root vouches for nobody.

The log is `<publisher>/log/sample`: nine entries and three signed heads. Its times are the generator's own (`context.json`). The log began ten minutes before the generator ran, and all three heads were stamped a few minutes after they were made.

| Index | Entry | First head |
|---|---|---|
| 0 | trust list `sample-list` v1 | 4 |
| 1 | issuer A's key added (Ed25519) | 4 |
| 2 | issuer B's key added (ES256) | 4 |
| 3 | an attestation by issuer A, by salted hash | 4 |
| 4 | trust list v2 | 7 |
| 5 | issuer A's key rotated | 7 |
| 6 | an attestation by issuer B, **backfilled**: it claims 30 days before the log began, and says so | 7 |
| 7 | issuer B's withdrawal status list | 9 |
| 8 | **the planted backdated attestation**: it claims ten days before it was logged, and does not say so | 9 |

The log allows one day between a claimed time and its first witness (`maxBatchDelaySec`).

| File | What it is |
|---|---|
| `original/` | the log's files, as `kash log` writes them and a static host serves them |
| `mirror/` | a byte-for-byte copy: what an honest mirror holds |
| `tampered/altered` | entry 2's key id changed |
| `tampered/removed` | entry 5 removed |
| `tampered/reordered` | entries 1 and 2 swapped |
| `tampered/stranger` | the head of 9 replaced by one a stranger signed over the log's id |
| `tampered/split` | a second head of 9, signed by the log's own key, forked after the head of 7 over another ninth entry: a split view |
| `inclusion-attestation-ok.json` | entry 3 in its first head, 4 |
| `inclusion-later-head.json` | entry 3 in the head of 9: not its first, so its claimed time is not judged |
| `inclusion-trust-list.json` | entry 0 in the head of 9 |
| `inclusion-backfilled.json` | entry 6 in its first head, 7 |
| `inclusion-backdated.json` | entry 8 in its first head, 9: **caught** as `CLAIMED_BEFORE_WITNESS` |
| `consistency-4-7.json`, `-7-9`, `-4-9` | each later head extends the earlier |
| `sample-tsa-root.crt` | the SAMPLE authority's root certificate: the only trust anchor these tokens chain to |
| `context.json` | the identifiers, each entry's claimed time, each head's own and witnessed time, and the three salts with their record hashes |

```
attest log verify original --mirror mirror --tsa-root sample-tsa-root.crt
    # PASS: the log is whole; entry 8's claimed time is not supported
attest log verify original --mirror tampered/removed
    # FAIL: the mirror's first entries do not rebuild the signed root
attest verify inclusion-backdated.json --tsa-root sample-tsa-root.crt
    # FAIL: CLAIMED_BEFORE_WITNESS
attest verify inclusion-backdated.json
    # PASS: in the log; without --tsa-root no witness signature is checked, so there is no attested time to judge by
```

The salts in `context.json` exist only so the tests can show that a salted hash opens. In a real log the issuer keeps each salt beside its record and hands it to the record's holder. The log never sees one.
