# GP-6 vectors — the session anchor's second version

Generated once by `gen-anchor-vectors.ts` on 2026-10-10 and **never regenerated**: four of the five sessions are signed with keys that no longer exist. Everything here is a simulation (ECOSYSTEM d11), and nothing was witnessed by a public log — the witness is `none`, labelled *practice*.

One batch of five complete sessions, anchored in one RFC 6962 tree (`specs/session-receipt.md` §3, v1.1). Each receipt carries the batch's root and **its own audit path only**.

| File | What it is |
|---|---|
| `session-anchored-0.v2.json` | a coffee (`presence+flow`), leaf index 0 |
| `session-anchored-1.v2.json` | a guided day (`presence+process+flow`), leaf index 1 |
| `session-anchored-2.v2.json` | **PL-3's repair**: the six signed lines of `../exchange/session-receipt-complete.v1.json`, copied unchanged, with a second-version anchor in place of its first; leaf index 2 |
| `session-anchored-3.v2.json` | a grant tranche (`flow+process`, no place), leaf index 3 |
| `session-anchored-4.v2.json` | an alteration at a tailor's (`process+flow`), leaf index 4 |
| `batch.v2.json` | the anchoring host's own view of the batch — every session's id, parties and head. **Never shipped with a receipt**; here so the tests can show no receipt carries any of it |
| `context.v2.json` | a "now" |

```
attest verify session-anchored-2.v2.json      # PASS, and: batch : leaf index 2 in a batch of 5 — its own path reaches the batch's root
```

`../exchange` was read, never written: its files are byte-identical before and after this generator ran.
