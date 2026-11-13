# The holder contract — what a wallet holds, how a record arrives, how it leaves, whom it trusts, how a withdrawal is known

**`specs/holder-contract.md` — v1 · 2026-09-24 · PL-1 · verification in `@kashscript/attest/holder` (Apache-2.0).**
Decisions: ECOSYSTEM d27, d28, d41, d42 §2, d44, d47 (a, e, f, g), d49 · related: [countersign](countersign.md), [ADR-0018](../docs/adr/0018-countersign-primitive.md).

> **What exists, and what does not.** The formats and every verification step below are built in attest source (`0.2.0-alpha.0`), with conformance vectors, and **unpublished** — a prerelease publish is founder-terminal. No wallet (PL-6), issuer offer endpoint, trust-list publisher (PL-7) or status-list host exists. Nothing here has run with a person.

This contract is written so that **a stranger can build a competing wallet** from it (d42 §2, rule 3). Everything a wallet must *check* is in attest, free and offline. Everything a wallet or issuer must *do* is stated here.

## 0. The rule: records stay what they are

A wallet holds each artifact **exactly as its issuer signed it**, beside a small **holding manifest** the wallet writes itself. Nothing is re-wrapped, re-signed or re-encoded. The manifest is unsigned and **trusted for nothing**: every field is either recomputed from the artifact and compared, or reported as the holder's own assertion. Presentation (PL-3) derives answers from records; it never replaces them.

### What a wallet holds today

| Kind (`artifact.kind`) | Examples | How the signing key resolves |
|---|---|---|
| `dsse` | Oreoasis agent receipts, work records, predicates; Indorania visas and days | the signature's `keyid` |
| `countersign-bundle` | any subject with two signatures ([countersign](countersign.md)) | inside the `did:kash` identifiers, no lookup |
| `kash-event` | Indusland org labels, Tehzeeb marks | the header's `iss` |
| `indus-token` | IPOE1, IGEO1, IVFC1, IBPS1 | the token header's `kid` |
| `sd-jwt` *(v1.1)* | predicate credentials, thank-yous ([presentation](presentation.md), [thank-you](thank-you.md)) | the issuer JWT's `kid` or `iss` |
| `session-receipt` *(v1.1)* | a session both parties signed ([session receipt](session-receipt.md)) | the two parties' `did:kash`; complete is `countersigned`, pending never is |

**Keys resolve in one order**, and every report names the step that answered:

1. **self-certifying** — a `did:kash:<base58>` carries its own key.
2. **trust-list** — a key named by a verified, current trust list whose publisher the verifier pinned. From an unpinned list it is reported as `unpinned-trust-list`.
3. **held-key** — a public key the holder kept (for example their own device key). It verifies a signature; it never makes the signer listed.

Signers are not uniformly self-certifying today — agent receipts sign as `did:kash:agent:<hex>`, work records as an opaque actor id, Indus tokens by JWKS `kid` — which is why steps 2 and 3 exist.

### The attestation class, computed from the bytes

| Class | When | Consequence |
|---|---|---|
| `countersigned` | a countersign bundle whose two-signature proof verifies | the only class that is proof under d41 |
| `device-asserted` | signed only by the holder's own device or browser: **IGEO1**, Indorania visas and days | never passes as countersigned; never earns a thank-you (d49 rule 5); needs no listing |
| `issuer-signed` | everything else that verifies | one signature: a claim by its issuer |

A manifest that claims a stronger class than the bytes show fails (`MANIFEST_CLASS_MISMATCH`).

## 1. The handoff

Built on **OpenID for Verifiable Credential Issuance 1.0 (OID4VCI)**, pre-authorized code flow. Nothing is invented where that standard already speaks. *It is not conformant:* the OpenID Foundation's suites were run on 2026-10-10 and do not pass (`docs/conformance/2026-10-10`); HAIP's wallet attestation is the one thing below this contract refuses.

1. **The offer.** The issuer creates a Credential Offer (`credential_issuer`, `credential_configuration_ids`, `grants` → `urn:ietf:params:oauth:grant-type:pre-authorized_code`). It renders the **same offer three ways**: a QR code, an `openid-credential-offer://` deep link, and an `https` link for SMS or a claimable file (d42 §7, d47(f)). OID4VCI offers carry no signature and this contract adds none: the wallet establishes authenticity on receipt, by verifying the record.
2. **Redeem.** The wallet exchanges the pre-authorized code at the issuer's token endpoint, then sends a Credential Request whose **key proof** (`typ: openid4vci-proof+jwt`, over the issuer's nonce) is signed by **the relationship key** — a key the wallet made for this issuer alone (d41, d47(g)). Its `kid` is that key's `did:kash`. **Never a global identifier, never a wallet-instance id.** Issuers MUST allow anonymous pre-authorized access (`pre-authorized_grant_anonymous_access_supported: true`), so no wallet `client_id` is ever sent.
3. **Receive.** The Credential Response carries the artifact **unmodified** under one format profile, **`kash-artifact`**, defined here through OID4VCI's extension point for formats. Its credential configuration names the registered DST (`dst`). The response MAY carry `kash_retention_until` (unix seconds) — the issuer's retention (d27.5), which the wallet records as `issuer-declared`.
4. **Verify, then store.** The wallet runs `verifyHeldRecord` before it stores anything, and stores the artifact beside its manifest.

**Offers are single-use and expire.** The pre-authorized code is consumed on first redemption. Recommended lifetimes: minutes for a QR shown at a counter, at most days for a link sent by SMS. An expired or consumed offer returns the standard error and nothing else.

**No third party learns the relationship key.** The offer carries no key. A `credential_offer_uri`, if used, points only at the issuer's own host. The wallet talks to the issuer directly — no relay, no wallet-provider backend, no analytics. A push notification may say "you have something to collect", never the offer or the key. Wallet attestation, which would identify the wallet instance, is not used.

**Minors — the handoff must not become a side door.** An issuer mints an offer only through the same gates as issuance itself. Indusland's triple gate means **no presence records for `is_minor`**, so no presence offer may be minted for such an account. There is no generic "send any record to a wallet" endpoint. The wallet collects no age, name or origin.

Not in v1: deferred issuance, batch issuance, the notification endpoint.

## 2. The holding manifest and the export bundle

### The holding manifest

| Field | Meaning | What the verifier checks |
|---|---|---|
| `recordId` | SHA-256 hex over RFC 8785 JCS of the artifact (over the UTF-8 of a token string). Local to the wallet; never sent anywhere. **Counting is by content identity, not record id** (`contentIdOf`; AU-3, A7-03): the PAE bytes a DSSE or countersign subject's signers signed, a Kash-Event's JCS of `{header, body}`, an SD-JWT's issuer JWT — so a copy re-wrapped with an extra field or a junk signature entry, or shown bare and countersigned, is one record wherever records are counted | recomputed — `RECORD_ID_MISMATCH` |
| `issuer` | the signer the record is attributed to | must equal the signer the bytes name — `MANIFEST_ISSUER_MISMATCH` |
| `relationship` | the holder's relationship identifier for this issuer, or null | holder's assertion |
| `type` | `{tag, family, attestation}` | tag and family from the bytes; class computed — `MANIFEST_TYPE_MISMATCH`, `MANIFEST_CLASS_MISMATCH` |
| `receivedAtUnix` | when the wallet stored it | holder's assertion |
| `expiresAtUnix`, `retentionSource` | when the wallet deletes it; `record` / `issuer-declared` / `none-declared` | never later than an expiry signed into the record — `RETENTION_EXTENDED`, `RETENTION_SOURCE_UNSUPPORTED` |
| `status` | a copy of the record's own signed `credentialStatus`, or null | must equal the signed value — `MANIFEST_STATUS_MISMATCH` |
| `listing`, `keptUnlistedAtUnix` | `listed` / `unlisted`, and when the holder chose to keep an unlisted record | `listed` needs a presented list — `LISTING_CLAIM_UNSUPPORTED`; unlisted needs the choice — `UNLISTED_WITHOUT_CHOICE` (device-asserted records excepted) |

### The export bundle — `kashscript-holder-export/1`

One file, the whole wallet: `formatVersion`, `exportedAtUnix`, `records[{manifest, artifact}]`, `keySuccession[]` (`kash-key-claim-v1` pairs), `trustLists[]`, `statusLists[]` (prefetched), `revocations[]` (presented), `heldKeys[]` (public only) and `encryptedKeyBackup`. *(v1.1)* An optional `presentationLog[]` — the holder's own log ([presentation §5](presentation.md)), exported with the wallet and never sent anywhere; an invalid log fails the file (`PRESENTATION_LOG_INVALID`).

*(v1.3, PL-2)* **Keys of either type.** A held key's `alg` is `Ed25519` (32-byte `publicKeyHex`) or `ES256` (the 33-byte compressed P-256 point in hex); every key verifies only its own algorithm (ADR-0020). **`keySuccession[]` holds either kind of claim** — a prior-key pair, or a helper-quorum claim carrying its helper set ([recovery.md](recovery.md)) — and every claim in the file is verified together: two successors for one key fail the file (`KEY_SUCCESSION_CONFLICT`). **An optional `recoveryHelpers[]`** carries, for each of the holder's current keys, `{counterparty, helperSet}`: the `kash-recovery-helpers-v1` set the key signed in advance, and the holder's own unsigned label of where that key is used — so a new phone knows which place to show each succession to. The label is the holder's assertion, like a manifest's `relationship`, and **never goes to a helper**. A set that does not verify fails the file (`HELPER_SET_INVALID`). Absent when empty, so every v1 file and vector is unchanged.

- **Byte-stable.** Records sorted by `recordId`, then RFC 8785 JCS, no trailing newline (`serializeHolderExport`). The same holdings always give the same bytes. This is safe because every artifact in use signs payload bytes, canonical bytes or a verbatim string — never the JSON around it.
- **Private keys only in the backup, only on request.** `encryptedKeyBackup` is null unless the holder asked. When present it is JWE flattened JSON (RFC 7516): `PBES2-HS256+A128KW` under a passphrase, or a key-wrap under the account's end-to-end key (d47(f)), with `A256GCM`. The hardware root key is non-extractable and is never in it. Recovery by succession stays the default (d47(g)); the backup is an escape hatch the holder chooses. *(v1.3)* **A key held in a secure chip is never in it** — it cannot leave the chip; after a lost phone it is succeeded, never copied. The plaintext stays Ed25519 seeds. *(v1.2)* Its plaintext is UTF-8 JSON, `{"keys":[{"keyid","alg":"Ed25519","privateKeyHex"}]}` — each key's 32-byte seed in lowercase hex, `keyid` its `did:kash` or the id it was held under — exactly as the v1 vector writes it. A PBES2 backup's `p2c` is at least 1,000; `@kashscript/wallet` writes 600,000 and reads up to 10,000,000. A private key anywhere else (`privateKey*`, `secretKey`, `seed`, `masterSeed`, a JWK `d`) fails the file: `PLAINTEXT_PRIVATE_KEY`.
- **Expiry is real (d27.5).** The wallet deletes a record at `expiresAtUnix`. Importing an export drops what has expired. An export can never carry a record past its retention: `RECORD_PAST_RETENTION` if it expired at or before `exportedAtUnix`.
- **An export is not a presentation.** It carries every relationship identifier the holder has. It goes to the holder's own next wallet, never to a verifier.

**Verifying:** `attest verify export.json [--trust-publisher <did>]`. No key on the command line, and nothing fetched. Exit 0 = PASS, 1 = FAIL, 2 = usage (attest's 3, INTEGRITY ONLY, is for an audit bundle or a report checked with no key; an export's keys are self-certifying or carried in the file, never that). A revoked record is a status, not a broken file: the file still passes and the record says *revoked*. One record that cannot be read — a payload that is not JSON, a container nobody could have signed — is `MALFORMED_ARTIFACT` on that record alone; every other record is still judged (AU-3, A7-04).

## 3. The trust list

A DSSE envelope, `payloadType` **`application/vnd.kash.trust-list+json`**, signed by its publisher's self-certifying `did:kash`: `format: kashscript-trust-list/1`, `listId`, monotonic `version`, `publisher`, `issuedAtUnix`, a validity window, and `issuers[{issuerId, label, keys[], dsts[], window}]`. Signed, versioned, cacheable offline.

- **It is a policy, not the format (d47(e)).** The record format stays holdable by any wallet. A holder may keep a record from an unlisted issuer **by explicit choice**, and it is marked `unlisted`.
- **Grants are exact tags.** Each issuer is listed for the registered DSTs it names, never a family — a `dsse-type` grant would let one member vouch for another's payloadType. An unregistered tag makes the list invalid.
- **An unlisted issuer never renders as trusted.** Only a list whose publisher the verifier **pinned out of band** makes a record listed. attest ships no pin (no ecosystem publisher key exists until PL-7); the wallet ships with its publisher's DID. An unpinned list is reported as that publisher's word, and every record shows as unlisted.
- **Honest limit:** offline, a verifier cannot know that a newer version exists. It uses the highest version presented, and a list outside its window lists nobody.

## 4. Status and revocation — the one check that may touch the network

**Standard: W3C Bitstring Status List v1.0.** A record carries a `BitstringStatusListEntry` as `credentialStatus` inside its own signed payload (`statusPurpose`, `statusListIndex` as a decimal string, `statusListCredential` = the list URL). The issuer publishes a DSSE envelope, `payloadType` **`application/vnd.kash.status-list+json`**, whose payload mirrors `BitstringStatusList`: `encodedList` is `u` + base64url of the GZIP'd bitstring, and index 0 is the left-most bit. The envelope is ours, so this is *aligned to* the standard, never a Verifiable Credential. It was chosen over the IETF OAuth Token Status List because it is a published W3C specification with the size floor built in. PL-3 may map to the IETF form for SD-JWT presentations.

**Status lists correlate, so:**
- **never a per-record status URL.** One list is shared by all of an issuer's records of a kind and period.
- **at least 131,072 entries** — the standard's own floor, enforced when signing and when verifying (`STATUS_LIST_TOO_SMALL`).
- **indexes assigned at random**, never in issue order.
- **the holder prefetches** the lists its records point at on its own schedule, never at the moment of presenting, and carries them. A carried list is checked exactly like a fetched one.

**The verdict always names what it rests on:**

| State | Text |
|---|---|
| `not-revoked` | *valid unless revoked, as of \<list time\>* (carried, or fetched from the issuer) |
| `revoked` / `suspended` | *revoked as of \<list time\>* |
| `withdrawn` | a presented withdrawal that predates the countersignature |
| `unknown` | the list was not presented, or is past its `validUntil` — *not checked*, never a guess |
| `no-status-entry` | the signed record carries no entry — withdrawable only by expiry or a presented revocation |

The list time is the issuer's own claim. **`fetchStatusLists` is the only function in attest that takes a `fetch`**, and the CLI calls it only for `--check-status`. Everything else is offline.

**How this squares with ADR-0018**, which rejected a hosted status endpoint under d28: the list is the **issuer's**, never ours; a record's signature verifies without it; status is a separate verdict with its own time; and a list can be carried as well as fetched. Indorania's uptime is never a condition of checking anything.

**The existing withdrawals, mapped unchanged:**
- **Countersign withdrawal** (`kash-countersign-withdrawal-v1`) — presented inside its bundle. If it predates the signing, the record's signatures still verify and its status is `withdrawn`. If it is dated after, the record stands, and the report says so.
- **Tehzeeb mark revocation** (`indus.mark.revoke.v1`) — presented in `revocations[]`. It revokes the mark whose `SHA-256(canonicalJson(mark))` equals its `markSha256`, signed by the mark's own issuer. A revocation of another mark, or signed by anyone else, revokes nothing.
- **Finding, not changed here:** Indusland answers mark status per mark id (`/api/tehzeeb/marks/[id]`) — a per-record status URL, which this contract forbids for new work.

Records already signed carry no entry. They cannot gain one without re-signing, which is forbidden, so their verdict says `no-status-entry`.

## 5. The DSTs

Registered in `@kashscript/attest/dst` before anything signed under them:

| DST | Family | Signed by |
|---|---|---|
| `application/vnd.kash.trust-list+json` | `dsse-type` | the trust list's publisher |
| `application/vnd.kash.status-list+json` | `dsse-type` | the issuer of the records it covers |

## 6. The edges, and where each one holds

| Edge | Where it holds |
|---|---|
| Every existing artifact verifies untouched | each kind goes to its existing verifier unchanged; the vectors copy the existing fixtures and Oreoasis envelopes byte for byte, and a test pins the fixtures' hashes |
| Status lists correlate | §4: no per-record URL, 131,072-entry floor, random indexes, holder prefetch |
| The handoff leaks no relationship key | §1: no key in the offer, direct to the issuer, anonymous pre-authorized access |
| Expiry is real | §2: `RETENTION_EXTENDED`, `RECORD_PAST_RETENTION`, import drops expired |
| An unlisted issuer never renders as trusted | §3: only a pinned list lists; the CLI never prints *listed* otherwise |
| IGEO1 is device-asserted | §0: the class comes from the bytes; `MANIFEST_CLASS_MISMATCH` |
| Minors | §1: offers only through issuance's own gates |

## 7. What comes later, and what this does not do

- **PL-2** adds ES256 beside Ed25519. Keys here already carry `alg`, and attest will take the algorithm from the key, never from the envelope. *(Done 2026-10-01 — v1.3.)*
- **PL-3** adds presentation, the ask exchange, the session receipt and the thank-you as formats. A presentation derives from held records; it never replaces or re-signs them.
- **Not built:** the wallet (PL-6), issuer offer endpoints, the trust-list publisher and its key (PL-7), and status-list hosting.

## 8. Conformance vectors

In `packages/attest/test/vectors/holder/` (see its README): a trust list, a 131,072-entry status list, a twelve-record export holding every kind above, and an export with a real JWE backup. They are generated once and never regenerated.

## Changelog

| Version | Date | Change |
|---|---|---|
| **v1.3** | 2026-10-01 | Additive (PL-2): held and trust-list keys may be `ES256` (33-byte compressed P-256, hex); `keySuccession[]` holds prior-key and helper-quorum claims, verified together (`KEY_SUCCESSION_CONFLICT`); an optional `recoveryHelpers[]` of `{counterparty, helperSet}` (`HELPER_SET_INVALID`); keys held in a secure chip are never in the backup. A runtime without Ed25519 reports `RUNTIME_CANNOT_CHECK`, never an invalid file. Every earlier file and vector verifies unchanged. |
| **v1.2** | 2026-09-25 | Additive, no verifier change (PL-6): §2 states the encrypted backup's plaintext and the `p2c` range, as the v1 backup vector already writes them, so a stranger's wallet can read one. |
| **v1.1** | 2026-09-25 | Additive (PL-3): the export may hold `sd-jwt` credentials and `session-receipt`s, and carry an optional `presentationLog`. An SD-JWT's signed `exp` is the retention ceiling, as a record's own expiry already is. Every v1 file and vector verifies unchanged. |
| **v1** | 2026-09-24 | The handoff (OID4VCI 1.0 pre-authorized, profile `kash-artifact`), the holding manifest and `kashscript-holder-export/1`, the trust list, and status lists aligned to W3C Bitstring Status List v1.0. Verification in `@kashscript/attest/holder` `0.2.0-alpha.0`, with vectors — **unpublished**. |
