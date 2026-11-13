# The cohort profile — station zero's record of a finished cohort

**`specs/cohort-profile.md` — v1 · BUILT 2026-10-08 (KS-R1) · `@kashscript/attest` `0.2.0-alpha.3`, `./profiles` (Apache-2.0).** ECOSYSTEM d43, d54(g), d59, d62(d)1–3, d63(b)–(c).

> **Not available to anyone yet.** npm has attest `latest 0.1.8` and `alpha 0.2.0-alpha.2` `[v 10-08, npm view]`; `0.2.0-alpha.3` is in this repository only. Publishing is founder-terminal. Until it lands, no issuer outside this monorepo can validate a cohort record, and no surface may describe one as available.

## What it is

The record a graduate holds in Chakor (d54(g)). It says three things:
- a cohort was finished;
- it ran under a published syllabus, at a named version;
- the teacher's organisation and the station each countersigned it with their own keys.

It is **the process record only**:
- the cohort's fee is a `terms` agreement (d59(a)), invoiced by hand until incorporation (d50(h));
- the capstone a client accepts is its own Oreoasis *Accepted* record (d63(c)).

## Why a profile, not a tag

attest's registry is append-only, and **reusing a registered type through a profile is preferred over a new tag** (d59(e)). The Oreoasis work record — payloadType `application/vnd.oreoasis.work-record+json`, claim `oreoasis.work-record/1` — already carries what this record needs:

| The founder's four | Where it lives |
|---|---|
| Who learned — the holder | `actor.id` |
| What process — the syllabus, by version (d43) | `rule {id, version, hash}` |
| Who countersigns — the station and the teacher | `meta.teacherOrg` and `meta.station`, and the bundle's two acceptances |
| An expiry (d27) | `meta.expiresAt` |

`meta` is the claim's declared extension slot, so the profile changes nothing in Oreoasis's claim. The profile names itself in `meta.profile`: **`kashscript-cohort/1`**.

**One honest gap.** attest's holder machinery reads a record's own expiry only from a top-level `expiresAt` ([holder contract §2](holder-contract.md)), and a work record has none. So:
- the issuer declares `kash_retention_until` equal to `meta.expiresAt` in the handoff;
- the wallet deletes the record at that time.

A top-level field would have changed Oreoasis's claim, which is not this profile's to change.

## The fields

| Field | Rule |
|---|---|
| `spec` | `"oreoasis.work-record/1"` |
| `receiptId` | a ULID |
| `org` | optional. The issuer's own label for itself (Oreoasis writes its slug). Never checked against anything |
| `actor` | exactly `{ class: "person", id: <the holder's relationship did:kash> }`. No `authority` (this is not a licence) and no agent fields |
| `shape` | `"followed"`: the learner followed the syllabus in force |
| `rule` | `{ id, version, hash }`: where the syllabus is published, its version, and the SHA-256 (lowercase hex) of its exact published bytes |
| `action` | pinned: `{ type: "cohort.complete", summary: "Finished a cohort under the syllabus and version named in this record." }`. The record carries no free text |
| `inputs`, `outputs` | `[]`. Work products, the capstone among them, are their own records |
| `status` | `"completed"`, and nothing else |
| `timestamp` | when the cohort finished, ISO-8601 in UTC |
| `meta` | exactly `{ profile: "kashscript-cohort/1", teacherOrg: <did:kash>, station: <did:kash>, expiresAt: <ISO-8601 UTC, after timestamp> }` |

**The shape is closed:**
- any key the table does not name is refused (`UNKNOWN_FIELD`);
- `prev` is refused too, because it would chain one learner's record to the next one's.

**Two families of names are refused wherever they sit** (`FORBIDDEN_FIELD`), whatever their casing. Matching is word by word, so `finalGrade`, `passMark` and `score_out_of_100` are caught and `passport` is not:
- **judgement** (d43, d51): grade, score, rank, rating, mark, percentile, gpa, points, level, result, merit, distinction, honours, pass, fail, attendance, performance, standing, and their forms;
- **payer** (d55(e)): sponsor, payer, paid, payment, fee, price, amount, cost, scholarship, funder, invoice, discount, waiver.

**The three DIDs** — the holder, the teacher's organisation and the station — are bare, self-certifying `did:kash` with no fragment, and all three differ.

**The payload is signed as RFC 8785 (JCS) bytes,** and a verifier refuses any other bytes (`NOT_CANONICAL`). Without that, a duplicate key such as `"status":"failed","status":"completed"` would let two parsers read two different records.

## Who signs

| Party | Signs | With |
|---|---|---|
| **The teacher's organisation** | the countersign request, and its own acceptance of it | its own DID — the one its records name |
| **The station** | its acceptance | the DID its charter names |
| **The holder** | **no part of the record** — only the key proofs that bind it and redeem it | the relationship key their wallet made for this issuer alone (d41, d47(g)) |
| **Anyone else** — Indorania, a sponsor, a second station | nothing; a verifier refuses it (`UNEXPECTED_SIGNER`) | — |

- **Organisations sign as themselves** (d62(d)2), never with a per-ceremony key. Otherwise no published rule could later recognise *"countersigned by a chartered station"*, which is how a graduate becomes a member (d53, d62(c)5).
  - Both acceptances say `subject-generated`.
  - A key someone else minted for an organisation is refused (`DELEGATED_KEY`).
- **The teacher's organisation is the requester.**
  - A wallet names a held countersign bundle's issuer from the request's signer (the manifest's `issuer`, [holder contract §2](holder-contract.md)).
  - So the requester's key is the one a trust list must list for `application/vnd.oreoasis.work-record+json`, for Chakor to show the record as listed.
- **The subject starts unsigned, and ends with exactly two signatures.** Each sits beside an acceptance that states its time and its key's custody.
  - The countersign verifier allows this unchanged: it requires two keys over the same bytes, not that the requester signed the subject.
- **The holder signs no part of it.**
  - `@kashscript/wallet` receives only through OpenID4VCI and has no path to sign a subject for an issuer.
  - A holder-signed subject would also make the wallet name the learner's own key as the issuer.
  - The holder's signatures are the key proofs of the issuance sequence, each made with the relationship key.
- **The two organisations must differ.** One organisation cannot countersign itself (d26). A station that teaches its own cohort needs another independent countersigner, and that is not this profile.

## The issuance sequence

Delivery into Chakor needs an **online issuer**: the wallet receives only through OpenID4VCI, from the issuer's own HTTPS origin (d62(d)1; `packages/wallet/src/receive.ts`).
- **OA-S1 builds it at Oreoasis** (d63(b)).
- **KS-R2b** is the fallback.
- **`kash` (KS-R2)** writes the same record as a file, because paper is the floor. It never delivers into a wallet.

1. **Binding, at enrolment.**
   - The learner connects Chakor to the issuer's origin.
   - The wallet makes a relationship key for that origin alone and signs the OpenID4VCI key proof with it: `typ: openid4vci-proof+jwt`, over the issuer's nonce, `aud` = the issuer.
   - The issuer verifies the proof and keeps its `kid`, a `did:kash`, with the enrolment. Nothing else identifies the learner here.
2. **The completion record, bound to that key.**
   - When the cohort ends, the teacher's organisation composes a claim (`buildCohortClaim`) for each learner who **finished and is bound**, with `actor.id` set to the bound key.
   - It makes the unsigned subject (`cohortSubject`).
   - A learner who stopped, or never connected a wallet, gets no record, and nothing is composed about them.
3. **Both countersignatures.**
   - The teacher's organisation signs a countersign request over the subject (identity-server's ceremony), then accepts it itself, where it stands, with its own key.
   - It sends the station the link: hosted, or carried as bytes with no server (`kash countersign`).
   - The station accepts with its charter's key.
   - **Either may decline. A decline leaves no trace (d49), and then there is no record.**
   - In hosted mode, mark the request answered after the station's acceptance. The teacher's own acceptance never used the link.
4. **The offer.**
   - Only now does the issuer assemble the bundle (`kashscript-countersign/1`) and check it with `verifyCohortRecord`.
   - It mints a single-use pre-authorized offer (`kash-artifact`, `dst` = the work-record tag) and declares `kash_retention_until` equal to the record's expiry.
   - At redemption it releases the bundle **only to a key proof whose `kid` is the record's `actor.id`**: `verifyCohortRecord(bundle, { holderDid })`.

The request's `statement` and `disclosures` travel inside the record for as long as it is held. So they describe the cohort, never the learner: no name, no grade, no payer.
- A disclosure label with a forbidden word fails the record.
- The teacher's organisation tells the station which learner each link is for out of band. Nothing in the record says.

## Verifying

```
attest verify cohort-record.json      # no --key, no network, no service
```

**The CLI** recognises a countersign bundle whose work record names this profile, and runs `verifyCohortRecord`, which checks in order:
1. every countersign check ([countersign.md](countersign.md));
2. the profile;
3. who signed, against who the record says signs.

Exit 0 = PASS, 1 = FAIL, 2 = usage or IO (attest's 3, INTEGRITY ONLY, never applies here: every key comes out of a `did:kash`). A plain countersign bundle prints exactly as before. The output ends with the plain layer — who signed, what was checked, what this does not prove — then `RESULT:`. Since AU-3 the teacher's organisation's own acceptance is reported `independent: false` — a signature over its own request, which the profile expects — and a record with that acceptance alone fails as `COUNTERSIGNER_IS_REQUESTER` beside the profile's `MISSING_COUNTERSIGNATURE` for the station.

**Expiry is reported apart from integrity**, as for a session receipt. Past `meta.expiresAt`:
- the report says `expired`;
- the CLI prints `RESULT: PASS (expired — it no longer attests)`;
- a wallet deletes the record.

| Code | Means |
|---|---|
| `NOT_A_COHORT_RECORD` | not a countersigned work record naming this profile |
| `WRONG_SPEC`, `MISSING_FIELD`, `UNKNOWN_FIELD`, `BAD_VALUE` | the claim's shape |
| `FORBIDDEN_FIELD` | a judgement or payer name, in the claim or a disclosure label |
| `NOT_FINISHED` | any status but `completed` |
| `NOT_CANONICAL` | signed bytes that are not JCS |
| `WRONG_ISSUER` | the request was not signed by the teacher's organisation |
| `MISSING_COUNTERSIGNATURE` | the teacher's organisation or the station has not countersigned |
| `UNEXPECTED_SIGNER` | anyone else signed, or one of them signed twice |
| `DELEGATED_KEY` | an organisation signed with a key someone else minted |
| `COUNTERSIGNED_BEFORE_FINISH` | an acceptance dated before `timestamp` |
| `NOT_THIS_HOLDER` | the record names another key than the `holderDid` passed in |

## What the record does not prove

- **How well anyone learned.** It carries no grade, score or rank, and proves no skill level (d43, d51). It says the cohort was finished, under that syllabus version.
- **Who the holder is.** It names a key their wallet made for this issuer, and a key is not a person.
- **That the keys belong to those organisations.** A charter, or a trust list the verifier pinned, says which organisation holds a DID; this file does not.
- **Who paid, or whether a seat was sponsored.** It never carries that; sponsored seats are Duedale's (d55(e)).
- **That a capstone exists, or that a client accepted it.** That is its own record. This one never mentions it, so a client's decline leaves no trace (d49).
- **Attendance, effort or deviations.** It carries no activity and no counts (d43). A deviation during the cohort is its own record, which the learner keeps if they choose.
- **That it has not been withdrawn.** As with every countersign bundle, absence of a withdrawal cannot be proven offline.
- **When it was signed.** Signing times are the signers' own claims.

## What it does not protect

**Showing it links its holder (d62(d)3).**
- The record is the same bytes, naming the same holder key, for every verifier it is shown to. Two verifiers who compare notes can tell it is one person.
- The issuer knows whose key it is.
- A countersigned bundle cannot be re-keyed per verifier.

The tier-two circuit (`@kashscript/predicate`, d59(a)) will let a holder prove the facts without showing the record. Until then, show the record only where being recognised as its holder is fine. `verifyCohortRecord`'s notes say so on every run.

## Edge cases

- **Not finished, no record.** `status` is `completed` or the record is refused, and `buildCohortClaim` takes no status. There is no "failed" record, and a learner's stop is protected (d43).
- **A sponsored seat is never named.** No field carries a payer, and the payer words fail the record.
- **The fee is a `terms` agreement** (d59(a)), invoiced by hand (d50(h)). It is never an income-share agreement or deferred payment (d63(c)).
- **The teacher's organisation and the station are one organisation.** That is not this profile.
- **No `prev`.** A held record never points at another.
- **The expiry.** The teacher's organisation sets it, strictly after the finish. **Station zero's length is the founder's to set;** three years is a suggested starting point, not a rule.
- **The syllabus** is named by three things:
  - where it is published (`rule.id`) — the teacher's organisation's DID plus a path is recommended, in d60's style;
  - its version;
  - the SHA-256 of its published bytes, which a verifier who fetches it compares.

  Its review date lives in the syllabus itself (d43: every rule expires).

## Not in v1

- **The holder's own signature on the record.** It needs a wallet path to sign a subject for an issuer, and a wallet that does not then name the holder as the issuer.
- **Revocation by status list.** The record carries no `credentialStatus`; expiry and the countersign withdrawal do the work.
- **The holder contract reading `meta.expiresAt`.** Today the issuer's `kash_retention_until` carries it.
- **Presentation without linking** — the tier-two circuit.
- **A public syllabus record in muffler,** for `rule.id` to point at (d59(a)).

## Uplift note — the API a consumer takes

*(For OA-S1, KS-R2, KS-R2b and IN-S0. Nothing here moves money or scores a person.)*

```ts
// from "@kashscript/attest/profiles"  (also the root)  — ≥ 0.2.0-alpha.3
DST_WORK_RECORD, WORK_RECORD_SPEC, COHORT_PROFILE, COHORT_ACTION
buildCohortClaim({ holderDid, teacherOrgDid, stationDid, syllabus: { id, version, hash },
                   finishedAt, expiresAt, org?, receiptId? }): CohortClaim   // throws INVALID_INPUT
cohortSubject(claim): DsseEnvelope                  // unsigned; JCS payload
validateCohortClaim(payload): { ok, claim, violations }
isCohortRecord(value): boolean                      // structural only
verifyCohortRecord(bundle, { nowSec?, holderDid? }): Promise<CohortRecordReport>
//   { ok, countersign, claim, holderDid, teacherOrgDid, stationDid, syllabus,
//     finishedAt, expiresAtUnix, expired, violations, notes }

// from "@kashscript/identity-server" — the ceremony, unchanged
createCountersignRequest({ subject, requesterDid: teacherOrg, requesterPrivateKey, statement, disclosures? })
acceptCountersignRequest({ request, subject, signingKey: <the organisation's own key, custody "subject-generated"> })
decodeCompactCountersignRequest(compactB64u)        // the carried rendering, for `kash countersign`
assembleCountersignBundle({ subject, request, acceptances: [teacherOrg's, station's] })
```

**Two things a consumer must carry, not paraphrase:**
1. **What the record does not prove**, and its linkability, wherever it is shown. IN-S0's card says *no skill level, no grade*.
2. **Release only to the named key.** The offer goes only to a key proof from `actor.id`.

## Changelog

| Version | Date | Change |
|---|---|---|
| **v1** | 2026-10-08 | **Built (KS-R1).** A closed profile, `kashscript-cohort/1`, over the work record — no new tag (d59(e)). The teacher's organisation requests, and both organisations accept with their own keys (d62(d)2). The holder is named by their relationship key and signs only the key proofs. The issuance sequence is binding → record → both countersignatures → offer (d62(d)1). Judgement and payer names are refused anywhere, with canonical bytes only. The CLI checks the profile on any bundle that names it. The ceremony round trip is in `packages/identity-server/test/cohort-profile.test.ts`. `attest@0.2.0-alpha.3` — **not published**. |
