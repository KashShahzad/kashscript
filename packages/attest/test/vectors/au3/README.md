# AU-3 vectors — forgeries, aliases and re-wrappings the verifier refuses by name

Generated once by `gen-au3-vectors.ts` on 2026-11-12 and **never regenerated**: every key is fresh and thrown away, so a second run would change every byte. Everything here is a simulation (ECOSYSTEM d11): no real person, place or organisation. `expected.v1.json` says what each file must do; `test/au3.test.ts` holds the verifier to it. They answer AUDIT-2026-11-11's A7-01, A7-02, A7-04 and A7-05.

| File | What it is | Expected |
|---|---|---|
| `sdjwt-kid-not-iss.v1.txt` | A predicate (`answer: true`) signed by an attacker's key, with that key in `kid` and the victim's DID in `iss`, presented with a valid key binding — the forgery A7-01 names | `KID_NOT_ISSUER` |
| `sdjwt-kid-self-iss-listed.v1.txt` | A self-certifying `kid` beside a trust-listed `iss` (the listed key is in `context.v1.json`) | `KID_NOT_ISSUER` |
| `sdjwt-no-iss.v1.txt` | A credential with no `iss` at all | `ISSUER_KEY_UNRESOLVED` |
| `sdjwt-kid-fragment-ok.v1.txt` | `kid` is `iss#sig-1` — it selects among the issuer's keys | ok |
| `sdjwt-listed-iss-ok.v1.txt` | A listed issuer, resolved through `iss` alone | ok |
| `countersign-alias.v1.json` | The requester countersigns its own claim as `did:kash:X#c` — one key under two spellings | `COUNTERSIGNER_IS_REQUESTER`, one distinct key, no countersigner |
| `countersign-requester-accepts.v1.json` | The requester's own acceptance beside an independent one (the cohort profile's shape) | ok, two keys, the independent key the only countersigner |
| `countersign-junk-sibling.v1.json` | A valid bundle with a sibling signature that is not base64 | ok, two keys |
| `countersign-custody-missing.v1.json` | An acceptance that states no `keyCustody` | ok; custody `unknown`, not subject-held |
| `countersign-nonjson-subject.v1.json` | A subject whose payload is bytes, not JSON | ok as bytes, with a note; a wallet or a desk calls it malformed |
| `context.v1.json` | The public facts: the time to check at, the audience and nonce, the listed issuer's keyid and key, the parties' DIDs | — |

```
attest verify countersign-alias.v1.json               # 1 distinct key(s) … two-signature proof: NO … RESULT: FAIL (exit 1)
attest verify countersign-requester-accepts.v1.json   # the requester's own key marked as a signature, not a countersignature … RESULT: PASS (exit 0)
```
