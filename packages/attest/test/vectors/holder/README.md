# Holder-contract conformance vectors

Generated once by `gen-holder-vectors.ts` on 2026-09-24 and **never regenerated** — every signature uses a key that no longer exists, so a second run would change every byte. Everything here is a simulation (ECOSYSTEM d11): no real person, venue or organisation.

| File | What it is |
|---|---|
| `trust-list.v1.json` | A signed `kashscript-trust-list/1`. **Pin its publisher out of band:** `did:kash:CJyXiKAaH3EeBHm4ympbXJPBNE4JoTuA4QYVvRS5u3CT`. |
| `status-list.v1.json` | A signed `kashscript-status-list/1`: 131,072 entries, issuer `did:kash:AqpfoVEdhjc73G3n4HqgmjZZy7dYMhqs3SaQPoWLvFRv`, index 90211 revoked, index 17403 clear. |
| `holder-export.v1.json` | A `kashscript-holder-export/1` with twelve records, written as its exact canonical bytes (one line, no trailing newline). |
| `holder-export-backup.v1.json` | The same format carrying a real JWE key backup (`PBES2-HS256+A128KW` / `A256GCM`). Test passphrase: `test vector only — never a real backup`. |
| `source/` | The Oreoasis agent-receipt and work-record envelopes, **copied unmodified** from `Oreoasis 2.0/packages/sdk/vectors/`, with their public keys (not their private keys). |

The export holds one record of each kind the contract must carry untouched. **Copies, not re-made:** the IVFC1 token and the countersign bundle (from `../../fixtures`), and the two Oreoasis envelopes (from `source/`). **Samples built with each issuer's exact construction:** IPOE1, IGEO1, IBPS1, two predicates carrying a status entry, an Indorania visa and day, and a Tehzeeb mark with a presented revocation. It also carries a key-succession pair, the trust list and the status list above.

```
attest verify holder-export.v1.json --trust-publisher did:kash:CJyXiKAaH3EeBHm4ympbXJPBNE4JoTuA4QYVvRS5u3CT
```

Expected: `RESULT: PASS`, `network: none`, `canonical bytes: yes`. Without `--trust-publisher` it still passes, but no record shows as listed.
