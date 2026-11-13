# PL-3 conformance vectors — presentation, sessions, thank-yous

Generated once by `gen-exchange-vectors.ts` on 2026-09-25 and **never regenerated** — every signature uses a key that no longer exists. Everything here is a simulation (ECOSYSTEM d11). `context.v1.json` holds the public facts a verifier would already know: the issuer, each verifier's identifier and the nonce it sent, and a "now".

| File | What it is |
|---|---|
| `predicate-held-a.v1.txt` | a held predicate credential (SD-JWT VC, every disclosure) |
| `predicate-presentation-a.v1.txt`, `-b.v1.txt` | two presentations by one holder to two verifiers, from two copies — they share no correlator |
| `predicate-presentation-c-records.v1.txt` | a presentation where the holder disclosed the record hashes; the Oreoasis work record in `../holder/source` binds to one |
| `predicate-presentation-revoked.v1.txt` | a copy whose index is set in the status list |
| `predicate-status-list.v1.json` | the issuer's 131,072-entry status list |
| `session-receipt-complete.v1.json` | a repair (`process+flow`): six lines, all signed by both, a disagreement line, closed, anchor recorded (not witnessed) |
| `session-receipt-pending.v1.json` | a coffee (`presence+flow`): the last line signed by the café only — pending, not proof |
| `session-line-items.v1.json` | the openings the person kept for the repair's two line items |
| `thank-you.v1.txt`, `thank-you-redemption.v1.txt` | a café's thank-you, and its redemption to the café |
| `thank-you-status-before.v1.json`, `-after.v1.json` | the café's redemption list before and after it honoured the voucher |
| `asks/` | a valid ask, a word-boundary case, one invalid ask per rule and per forbidden need; `expected.json` names the rule each breaks |

```
attest verify predicate-presentation-a.v1.txt --audience <verifiers.a.did> --nonce <verifiers.a.nonce> --status-list predicate-status-list.v1.json
attest verify session-receipt-complete.v1.json
attest verify thank-you-redemption.v1.txt --nonce <redemptionNonce> --status-list thank-you-status-before.v1.json
attest verify asks/invalid-forbidden-caste.json      # exit 1
```
