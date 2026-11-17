# @kashscript/attest — the Evidence Commons

**Verification is free.** Apache-2.0. The base every other KashScript protocol signs with.

One package that **signs, canonicalizes, witnesses, hash-chains, and verifies** the three
signing families the ecosystem uses — plus a standalone CLI and offline compat verifiers for the
artifacts the ventures already ship. Built in phase **M1** of the protocol Manifestation
([ADR-0016](../../docs/adr/0016-protocol-manifestation.md)); every API is derived from the venture
code that seeds it (Oreoasis, Duedale, Indusland), never invented.

## The three signing families

| Family | Signed bytes | Used by |
|---|---|---|
| **Kash-Event** | `Ed25519( DST\n ‖ JCS({header,body}) )` (via `@kashscript/identity-core`) | Duedale `kash-report-v1`/`kash-grant-v1`, Oreoasis ledger rows, Indusland org labels and Tehzeeb marks (`indus.label.v1`, `indus.mark.v1`, `indus.mark.revoke.v1`) |
| **DSSE + PAE** | `Ed25519( PAE(payloadType, bytes) )` — Sigstore-compatible | Oreoasis audit bundles |
| **Indus token** | `Ed25519( DST ‖ 0x00 ‖ headerB64u ‖ "." ‖ bodyB64u )` | Indusland IPOE1 / IVFC1 / IBPS1 / IGEO1 |

## What's inside

- **`dsse`** — DSSE envelopes + PAE (`signEnvelope` / `verifyEnvelope`).
- **`dst`** — the canonical Domain-Separation-Tag registry (new DSTs are registered here first).
- **`chain`** — RFC-8785 canonicalization + `chainBlockHash` + `sha256Hex` hash-chain helpers.
- **`witness`** — the public witnesses, read offline: OpenTimestamps proofs byte for byte, every operation recomputed (RIPEMD-160 included), and a supplied Bitcoin header's proof of work checked; RFC 3161 tokens read from their DER. The two networked clients, `stampOpenTimestamps` / `upgradeOpenTimestamps` and `rfc3161Stamp`, each take `fetch` explicitly. RFC 6962 trees, with inclusion and consistency proofs (`rfc6962Tree`, `rfc6962VerifyInclusion`, `rfc6962ConsistencyProof`, `rfc6962VerifyConsistency`). The older anchor client (Rekor → OpenTimestamps → offline `none`, a flat anchor root, a receipt store) stays for Oreoasis's audit anchor and verifies nothing.
- **`log`** — the trust log ([`specs/trust-log.md`](../../specs/trust-log.md)): four closed entries behind a guard, the salted record hash, checkpoints signed by the log's key, inclusion and consistency proofs, the time verdict that catches a backdated claim (`CLAIMED_BEFORE_WITNESS`), and `auditLog`, which rebuilds a log from its entries alone and compares a mirror. Pure: no file, no socket. **`log-files`** reads and writes a log's folder, and **`openssl`** checks an RFC 3161 token's signature against a root you name; both are Node only.
- **`signing`** — the one seam every DSSE and JWS signature goes through: Ed25519 or ES256, from a key's own bytes or through a callback for a key held elsewhere — a phone's chip, a key service — whose signature is checked before it is used. `SIGNATURE_PROFILES` names what may sign, and every JOSE header is checked against it before a key is touched; ML-DSA-65 is reserved, not built.
- **`ledger`** — verify a signed action-ledger row + the forensic chain scan (`forensicConsistencyScan`).
- **`bundle`** — verify a DSSE audit bundle end to end (signature + chain + anchor).
- **`countersign`** — the two-signature bundle and its offline verifier. A record signed only by the
  party it describes is self-attestation; `verifyCountersignBundle` checks that a *second, independent*
  key signed the same bytes, with no key material, no service and no lookup (ECOSYSTEM d26, d41).
- **`holder`** — the holder contract ([`specs/holder-contract.md`](../../specs/holder-contract.md)): the
  export bundle a wallet writes, the trust list it admits issuers by, and status lists aligned to the
  W3C Bitstring Status List. Offline, except `fetchStatusLists`, which takes `fetch` explicitly.
- **`sd-jwt`** — SD-JWT VC issuance, holder-bound presentation (KB-JWT) and offline verification, plus
  `linkabilityBetween`, which lists anything two presentations share that could link them.
- **`exchange`** — the ask and its eight rules ([`specs/presentation.md`](../../specs/presentation.md)), the
  predicate credential and its presentation, the holder's presentation log, the session receipt
  ([`specs/session-receipt.md`](../../specs/session-receipt.md)) and the thank-you
  ([`specs/thank-you.md`](../../specs/thank-you.md)). A session anchored in a batch carries the batch's
  root and its own path, and nothing of any other session (`kashscript-session-anchor/2`, `sessionAnchorBatch`).
- **`profiles`** — registered types reused with their open slots pinned, instead of new tags:
  `kashscript-cohort/1`, station zero's record of a finished cohort over the Oreoasis work record
  ([`specs/cohort-profile.md`](../../specs/cohort-profile.md)). `verifyCohortRecord` checks the two
  organisations' countersignatures, the profile, and who signed; the record carries no grade, score or rank.
- **`compat`** — verify shipped venture formats: the Duedale Every-Rupee report, Indus tokens, and the
  presented revocation of a Tehzeeb mark.
- **`ed25519`** — raw Ed25519 over arbitrary bytes (WebCrypto; the layer identity-core doesn't expose).
- **`ids`** — the canonical `ulid()` and `sha256Hex()` every venture imports instead of keeping its own.

## `ids` — one ULID, one digest, ecosystem-wide

```ts
import { ulid, isUlid, ulidTimeMs, sha256Hex, sha256HexOf } from "@kashscript/attest/ids";

const receiptId = ulid();                    // 26-char Crockford base32, time-sortable
await sha256Hex(bytes);                      // lowercase hex digest
await sha256HexOf("a string or bytes");      // the UTF-8 convenience
```

**Ventures consume these; they do not keep local copies.** ECOSYSTEM-AUDIT §2.1 found `ulid()`
implemented three times and §2.2 found `sha256Hex` re-implemented across the stack — and ECOSYSTEM
decision 13 (single source of truth) bans exactly that. This is attest's concern rather than a new
utility package because **an id that appears in a signed claim, and a digest a signature is taken
over, are part of the wire format**: a hash that drifts between the signer and the verifier is a
signature bug.

Pending venture swaps (delete the local copy in the same change — git remembers):

| Session | Venture | Local copy to delete |
|---|---|---|
| **OA-A5** | Oreoasis | `packages/sdk/src/receipt.ts` → its `ulid()` (its `sha256Hex` wrapper becomes `sha256HexOf`) |
| **OA-A5** | Oreoasis | `apps/oreoasis-core-host/src/ulid.ts` → `generateUlid()`; `ULID_ALPHABET` / `ULID_PATTERN` are re-exported here unchanged |
| **DD-A1** | Duedale | `ks-adapters/identity` → its local `sha256Hex` |

`ulid(nowMs?)` is signature-compatible with the Oreoasis SDK's copy, so each swap is an import line
plus a deletion. Indusland's Deno edge copies stay — decision 13's one documented exception, pinned
by a contract test. `packages/kash`'s `ulidFor(seed)` also stays: it mints a **deterministic**
ULID-shaped id from a content hash and is a different primitive, not a duplicate.

## The verifier CLI

```bash
attest verify <file> [--key <hex|host-key.txt|jwks.json>] [--signer-did <did>] [--offline]
                     [--trust-publisher <did>]... [--check-status]
                     [--audience <id>] [--nonce <n>] [--at <unix>] [--max-age <s>]
                     [--status-list <file>]...
                     [--header <file>]... [--tsa-root <pem>] [--max-batch-delay <s>]
attest log verify <dir> [--mirror <dir>] [--header <file>]... [--tsa-root <pem>]
```

Auto-detects and verifies **offline** a countersign bundle (a cohort record is one, checked against its
profile as well), a holder export, a trust list, a status list, an SD-JWT (a predicate or thank-you,
held or presented), a session receipt, an ask, a DSSE audit bundle, an Every-Rupee report, or an Indus
token. Exit codes: `0` PASS · `1`
verification FAILED (tamper) · `2` usage/IO · `3` INTEGRITY ONLY — a DSSE audit bundle or an
Every-Rupee report checked with no `--key` is consistent with itself, and its only key came from
inside the file, so it says nothing about who signed it (AU-3, A7-06). Public-log inclusion
(`rekor-cli` / `ots verify`) is delegated and printed as next-steps. `--check-status` is the only flag
that touches the network: it fetches the status lists a holder export points at and did not carry.

Since AU-3 (2026-11-12, AUDIT-2026-11-11) the verifier reports only what it verified: an SD-JWT's key
is `iss`'s and a `kid` must name `iss` (`KID_NOT_ISSUER`); countersign signers are counted and named by
the key a keyid resolves to, the requester's own acceptance is never a countersignature
(`independent`, `COUNTERSIGNER_IS_REQUESTER`); a record has one content identity for counting
(`contentIdOf`); every verifier that says *never throws* never throws; unstated custody is `unknown`;
and the Ed25519 acceptance rule is pinned (identity-core `ed25519-strict`, vectors under
`test/vectors/ed25519`). See [`docs/adr/0027`](../../docs/adr/0027-the-verifier-binds-the-issuer-to-the-key.md).

Since KS-Q4 (2026-11-18) a presented SD-JWT is checked only with `--audience` and `--nonce`, the
identifier you are and the nonce you sent, and its binding must be within `--max-age` seconds
(default 600) of now, or of `--at` for a file you check later. A header naming an algorithm outside
the profile registry is refused before any key is touched. A trust list's standing, class, grade and
scope are read, and a status verdict names its cache time. The trust log's checkpoint, inclusion proof
and consistency proof are detected and checked with the time verdict. `attest log verify <dir>`
audits a whole log from its files and compares a mirror; `--tsa-root` hands openssl the root an RFC 3161
witness must chain to, and `--header` hands in a Bitcoin block header for an OpenTimestamps witness.
See [`docs/adr/0030`](../../docs/adr/0030-the-trust-log-and-hardened-checking.md).

A countersign bundle needs **no `--key` at all** — `did:kash` is self-certifying, so every public key
is already inside the artifact:

```bash
attest verify countersign-bundle.json
#   signatures on it   : 2 distinct key(s) over the same bytes
#   two-signature proof: yes
#   key custody        : subject-generated
#   RESULT: PASS
```

It also prints what it *cannot* know — that no withdrawal being presented is not evidence that none
exists, and that signing times are the signers' own claims. See [`specs/countersign.md`](../../specs/countersign.md).

**Every verdict ends with the plain layer.** Just before the `RESULT:` line, three more lines say it in
words — *who signed*, *what was checked*, and *what this does not prove* (the ecosystem's law 9: a
tick is never alone). A failing check says *claims signed by* instead of *who signed*, because the
names are then only what the file says. A `did:kash` is a key, not a person, and the layer says so.
These are extra lines of text, nothing more: every line the CLI printed before still prints, the
exit codes are unchanged, and `RESULT:` is still the last line. There is no JSON output mode.

```bash
attest verify countersign-bundle.json
#   …
#   who signed         : did:kash:3gnt…, did:kash:Dnae…
#   what was checked   : the request signature; each acceptance — …; two keys over the same bytes
#   does not prove     : who holds a key, or whether what it signed is true; that nobody has withdrawn …
#   RESULT: PASS
```

## Status

`0.x` — the API stays `0.x` until each venture consumer swaps onto the published package and stays
green (consumer-as-acceptance, ADR-0016). The write-side action ledger lands in `@kashscript/hudhud`
(M5); issuance policy, storage adapters, and JWKS hosting stay venture-side.

Licensed Apache-2.0 — see `LICENSE`.
