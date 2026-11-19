# ADR-0031: One record type in three forms — the attestation and the mandate live in attest, under new tags, and the decision cites its mandate

- **Status:** Accepted
- **Date:** 2026-11-19
- **Decision drivers:** ECOSYSTEM d91(a) (one record type; references by hash and version; the mandate is a primitive; time from a witness; three terminal states) · d91(e) (Issue · Hold · Verify; standard wire formats; *Duedale must accept a receipt it has never seen from an engine it does not run*) · d91(f) (*a refusal carries a person-role signature and never a machine mandate*) · d59 (attest's registry is append-only; a profile is preferred over a new tag; lexicons holds public, organisation-authored records) · d85(l) (the decision's shape lives with the package that issues and checks it) · d26, d41, d43, d49, d62(d)2–3, d84 P3–P4, d88 · DUE-DILIGENCE-2026-11-09 C1, C6 · the prompt RW-14 (REAL-WORLD-SESSIONS-2026-11-09), whose plan the founder approved on 2026-11-19, and part one's adversarial review the same day.

## Context

d91(a) made one record type of everything the ecosystem signs. The kernel had no such record:
- Oreoasis's work record carried receipts in an engine's own shape.
- The predicate credential and the decision carried two kinds of attestation as SD-JWT VCs.
- References were six different hashes, none saying what kind of thing it named.
- No record could cite a mandate: Oreoasis's booking mandate is an access token that no record names.

Due diligence asked for two things: a normative specification with a schema a stranger can validate against (C1), and the privacy claim behind per-verifier copies (C6). The specification is [`specs/attestation/README.md`](../../specs/attestation/README.md).

## Decision

1. **Two new held records: `kash.attestation@1.0.0` and `kash.mandate@1.0.0`.** Both are closed shapes in the lexicons' DSL, with the cross-field rules a shape cannot write; each fault names its decision. The attestation covers receipts, findings, assurances and contests. **A decision keeps `kash.decision`**: it is mapped, never duplicated.
2. **They live in `@kashscript/attest/attestation`, and attest gains `@kashscript/lexicons` as a dependency.**
   - Not in lexicons' public set: d59 and d85(l) keep held records out of it.
   - Not in predicate: an issuer, a wallet and a desk all build on attest (d91(e)), and none should need the desk's package to read its own record.
   - lexicons has no dependencies, so there is no cycle. It is already published (`0.6.0-alpha.0`), so the publish order does not change.
   - The subpath is the only part of attest that reads lexicons. The root export is unchanged.
3. **New tags, not a profile.** Three rows are appended to attest's registry: `application/vnd.kash.attestation+json` (the record of truth), `application/vnd.kash.mandate+json`, and `https://kashscript.com/vct/attestation/1` (the copy). d59(e) prefers a profile over a registered type. The only candidate is Oreoasis's work record, an engine's shape, and the open protocol does not pin its one record type to one engine.
4. **The record of truth is made when the counterparty answers.**
   - The request names no counterparty. The counterparty signs the final bytes first, and the issuer (or its delegate, citing the mandate) signs last.
   - A declined or unanswered request leaves nothing, and a body one party signed alone is not a record (d49).
   - A receipt or a finding carries both signatures over the same bytes (d41). `verifyAttestationRecord` is the stranger's offline check of it, including a mandate presented beside it. What it cannot decide — the witnessed time, status, the counterparty's independence — it names in `notChecked`.
   - attest's countersign ceremony does not make this record as built. Adapting it is the engine's.
5. **Copies are made only from a record of truth that checks.**
   - `copyClaimsOf` verifies first and refuses otherwise.
   - A copy is an SD-JWT VC issued by the issuer's own key, one per verifier. What every holder of the kind shares is visible. What could join two copies is selectively disclosable: a private reference, the exact time, the record id, a mandate, a supersession, a contested decision.
   - The counterparty and its mandate are never in a copy.
   - A copy's dates are its own: the day it is issued, and that plus 90 days. A record that ends sooner gets no copy, so no copy carries anything of its record's dates.
   - Its `_sd` is padded to eight digests, so its length says nothing about which claims a record carries. It carries no status entry: a bit on a copy can be set only by an issuer that keeps which index belongs to which record. (Both came from part two's review, which found the first copies' `_sd` length and dates joining them.)
   - A copy is the issuer's word. Where the issuer is the holder, a door reads the record of truth instead (d26).
6. **The projection is an unsecured W3C VC 2.0 credential.** It has only the base context, never names the counterparty, and names the record's payload bytes by RFC 6920 named information.
7. **The mandate is not whiffin's.** d91(a) left the choice to KashScript. whiffin's grant dedicates *value* to a purpose (d59, d64(h)); this delegates the *authority to sign*. **d93(e)1, later, names whiffin for the host's mandate to the app; the founder ruled on 2026-11-20 that it is read as `kash.mandate` (ECOSYSTEM d91's dated note).**

   A mandate has one link (no chain in this version) and carries a status entry, so it can be revoked. Its floor is in the format:
   - an agent's, a desk's or another organisation's mandate names its outcomes, never *refused*;
   - an agent's covers receipts only;
   - a desk's covers decisions only;
   - every mandate is bounded and renews within 366 days.

   The counterparty's side may cite its own mandate (`counterpartyMandate`), for example a client company's employee.
8. ***Refused* lives in two places only.** One is a contest, which is the subject's own word, made against the rule whose recourse clause it invokes and naming the decision copy it contests. The other is a decision's `no` or `partial`, which a named person signs. A receipt is accepted or not yet: a decline leaves no trace (d49).
9. **`kash.decision@1.2.0`** lets a person's `decidedBy` cite the mandate its seat signed under, and the seat signs the citation with the body.
   - `validateDecision` refuses a citation not under the deciding organisation. With the mandate presented, it checks the mandate whole: the organisation's, to this seat, a seat's, covering this outcome, in force. Without it, it reports the mandate as not checked.
   - A standing decision cites none: its copy is the organisation's own signature.
   - Every 1.1.0 body is a 1.2.0 body, and 1.1.0 is frozen. A reader on predicate `0.3.0-alpha.3` refuses a 1.2.0 decision that carries a mandate.
10. **Node rule 10 reaches the new type.** A rule's query for an attestation pins its outcome to `accepted`, or the rule is refused (`ASKS_FOR_A_REFUSAL`).
11. **Worked examples and conformance cases ship with the specification**: `specs/attestation/examples/` (generated once, never regenerated, no key material) and `specs/attestation/tck/` (one file per new version, every attestation and mandate fault code exercised). Tests in attest and predicate check them, and the folder is exported to the public repository.
12. **Versions move in source only:** attest `0.3.0-alpha.1`, predicate `0.3.0-alpha.4`. Nothing is published.

## Consequences

- An engine can issue one record that a stranger checks, and a desk can read it through the presentation protocol without the issuer's database (d91(b)). Moving Oreoasis onto it is RW-24's. Nothing already signed is re-signed.
- attest's install now pulls lexicons; the subpath keeps the root's import graph as it was.
- RW-15 salts the references of the record kinds already in use. This record already commits to its private reference per copy.
- **d91(e) calls attest's envelope an internal convenience, while here the DSSE envelope is the record of truth**, because it is the one form that carries two signatures. The founder ruled on 2026-11-20 that the DSSE envelope stays the record of truth until a standard form carries two signatures (ECOSYSTEM d91's dated note), and confirmed this ADR's other rulings.
- Left open, in the specification's §4:
  - the ceremony that makes the record;
  - securing the projection;
  - the ZK tier for issuer-unlinkable copies and countersigned records without the counterparty's key;
  - chains of mandates;
  - a desk signing with its own key;
  - recognition between rules;
  - the grade's evidence;
  - digest agility;
  - who holds a copy.
