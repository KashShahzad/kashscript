# The countersign primitive — wire format, ceremony, and what a stranger checks

**`specs/countersign.md` — v1 · BUILT 2026-09-22 · spans `@kashscript/attest` (format + verifier,
Apache-2.0) and `@kashscript/identity-server` (ceremony, Apache-2.0). Decision record:
[ADR-0018](../docs/adr/0018-countersign-primitive.md).**

> **Not available to anyone yet.** `@kashscript/attest@0.1.5` is `latest` on npm and declares
> `"@kashscript/identity-core": "workspace:*"`, so `npm i @kashscript/attest` fails for everyone
> `[v 09-22]`. This repository is at `attest@0.1.6` / `identity-server@0.2.0` and **nothing has been
> published**. Until the founder publishes 0.1.6, a new DST is testable locally and **no stranger can
> verify a countersigned artifact**. No surface may describe this mechanic as available.
>
> **Update `[v 09-24, npm view]`:** `attest@0.1.6` and `attest@0.1.7`, and `identity-server@0.2.0`, are
> now on npm — `0.1.5` is still not deprecated. Duedale consumed it in its wave 1, and Oreoasis
> consumes it in `acceptance.ts`.

## Why it exists

ECOSYSTEM decision 26: **a record signed only by the party it describes is self-attestation**, and the
adversary in any real dispute is that party. Decision 41 makes it a rule — *two signatures or it is
not proof*. Decision 42 forbids any member building the mechanic locally, so it is here, once.

The shape decision 26 specifies: **a link, one click, signed — no install, no account, no password.**
If a counterparty must create an account, the countersignature never happens.

## The wire format

### The subject — unchanged

Whatever DSSE envelope a holder already signs. **No new `payloadType`, no new DST, no re-wrapping.**
The countersignature is an ordinary second entry in `signatures[]`, over `PAE(payloadType, payload)` —
the byte-identical bytes the first signature covered.

Both keys resolve from the `keyid` strings alone: `did:kash` is self-certifying, so verification takes
**no key material, no registry and no network** (d28).

### The four Kash-Event DSTs

Registered in [`@kashscript/attest/dst`](../packages/attest/src/dst.ts) first, by the standing rule.
All `kash-event` family: `Sign( DST ‖ JCS({header, body}) )` — Ed25519, or since PL-2 ES256, **the
algorithm taken from the signer's `did:kash`**, never from `signature.alg` alone (ADR-0020).

| DST | Signed by | Body |
|---|---|---|
| `kash-countersign-request-v1\n` | the holder | `requestId`, `requesterDid`, `subjectPayloadType`, `subjectDigestSha256`, `statement`, `disclosures[]`, `nonceB64`, `issuedAtUnix`, `expiresAtUnix`, `relationshipContext`, `withdrawalFeed` |
| `kash-countersign-v1\n` | the counterparty | `act:"countersign"`, `requestId`, `requestDigestSha256`, `subjectPayloadType`, `subjectDigestSha256`, `countersignerDid`, `keyCustody`, `signedAtUnix` |
| `kash-countersign-withdrawal-v1\n` | the holder | `act:"withdraw"`, `requestId`, `requestDigestSha256`, `withdrawnAtUnix` |
| `kash-key-claim-v1\n` | prior **and** successor, over one body — or, after a loss (PL-2), the successor and a quorum of helpers | `act:"claim-key"`, `priorDid`, `successorDid`, `successorKeyCustody`, `claimedAtUnix`; on the helper path also `by:"helpers"`, `helperSetSha256` ([recovery.md](recovery.md)) |

**The request names no counterparty.** Possession of a capability secret is the whole address; a
durable recipient identifier here would be a correlation key across every book (d41).

`requestDigestSha256 = SHA-256(JCS({header, body}))` of the signed request — one value binding the
nonce, the statement, the disclosures and the window together.

### The container — `kashscript-countersign/1`

```jsonc
{
  "formatVersion": "kashscript-countersign/1",
  "subject":     { "payloadType": "...", "payload": "<b64>", "signatures": [ {...}, {...} ] },
  "request":     { "header": {...}, "body": {...}, "signature": {...} },
  "acceptances": [ { "header": {...}, "body": {...}, "signature": {...} } ],
  "withdrawal":  null,
  "keyClaims":   []            // optional
}
```

**Unsigned on purpose.** Every part inside carries its own signature and every binding between parts
is checked by digest, so the container is trusted for nothing.

### Key succession — either path, any algorithm (PL-2, 2026-10-01)

A `keyClaims[]` entry moves a key's **future** authority to a successor. Two paths, one DST:

- **prior-key** — the prior key and the successor sign one body. Byte-for-byte the v1 claim.
- **helpers** — the prior key is lost; the successor and a **strict majority (at least two)** of the
  helper keys the prior key named **in advance** (`kash-recovery-helpers-v1`) sign one body, and the
  claim carries that helper set. The full rules are [recovery.md](recovery.md) §2–§3.

Either path crosses algorithms — **Ed25519 → P-256 and P-256 → Ed25519** — each signature checked
under the algorithm its signer's `did:kash` declares. The bundle's claims are verified **together**:
two successors for one prior are a conflict, and neither is trusted. **A `delegated-mint`
acceptance keeps its label after any claim, on either path** — and the report adds that the minter
could have made the claim (and, on the helper path, named the helpers). A claim re-signs nothing and
cures nothing behind it (ADR-0018).

## Verifying

```
attest verify countersign-bundle.json      # no --key, no network, no service
```

Exit 0 = PASS, 1 = FAIL, 2 = usage/IO (attest's exit 3, INTEGRITY ONLY, belongs to audit bundles and
reports whose only key came from the file — never to a countersign bundle, whose keys are
self-certifying). The checks, all offline: ≥2 **distinct keys** on the subject — **counted by the key a
keyid resolves to, never by its spelling**: `did:kash:X` and `did:kash:X#c` are one signer, and the
report names every signer in canonical form (AU-3, A7-02) · the request signed by its named
`requesterDid` · the request describes this envelope (type + digest) · each acceptance signed by its
named `countersignerDid`, binding this request and this subject · `issuedAtUnix ≤ signedAtUnix ≤
expiresAtUnix` · the countersigner's key among the subject's verified keys · **the countersigner is
not the requester**: the requester's own acceptance is a signature over its own claim, reported
`independent: false` and never a countersignature, and a bundle whose only verifying acceptance is the
requester's fails as `COUNTERSIGNER_IS_REQUESTER` (d26) · a presented withdrawal dated before a signing
→ `WITHDRAWN_BEFORE_SIGNING` · key claims verified as a pair · `keyCustody` read exactly —
`subject-generated`, `delegated-mint`, or `unknown` for an acceptance that states neither — and only
the first is subject-held (A7-05). Whether the requester signed the subject is reported
(`requesterSignedSubject`), not required: a cohort record's requester does, an organisation requesting
on its doer's record does not. **Every input returns a report** — `MALFORMED_BUNDLE` for what cannot
be read, a junk sibling signature or a subject that is not JSON included — and nothing is thrown
(A7-04).

**Presenting it at a door (KS-Q11, 2026-11-08):** a door's rule may name the bundle's holder as its countersigner — the one key whose acceptance here verifies, less the requester — so the party who accepted, not the one who asked, signs the presentation's binding. [rule.md](rule.md) §2.1 holds the rule; `@kashscript/predicate`'s `artifactHolderOf` reads it.

The report **always** states what it cannot know: *no withdrawal presented is not evidence that none
exists*, and *signing times are the signers' own claims*.

## The constitutional properties

| Constraint | How it holds |
|---|---|
| **Separate identifiers per relationship** (d41) | `HKDF-SHA256(masterSeed, SHA-256("kash-countersign-relationship-v1" ‖ requesterDid ‖ 0x00 ‖ contextLabel))`. The salt has **no input from the counterparty**, so nothing about them leaks across requesters. Stable within a relationship, unlinkable across. Without a wallet: a fresh key per request. *(Dated note, 2026-10-01, PL-2: a phone's secure chip cannot derive keys from a seed, so **the wallet generates a key per relationship and records it in its own registry** ([wallet.md](wallet.md) §3) — in the chip where it holds the algorithm. The HKDF path above stays, for **server-side ceremonies only**; identity-server's module header, "a wallet derives it", describes the path as written on 2026-09-22.)* |
| **The subject holds the key** (d27.1) | Default: generated on the counterparty's device, never transmitted (`subject-generated`). The server-minted `issueGuestDid` key is the **fallback** for a no-device counterparty and is labelled `delegated-mint` **inside the signed bytes**. A record signed under one is **not subject-held**, permanently. `claimCountersignKey` moves *future* authority only — see ADR-0018 for why it cures nothing retroactively. |
| **Non-participation stays viable** (d27.3, d42) | Declining produces **no artifact and no store write**, and leaves stored state byte-identical. A decline is indistinguishable from silence and from an unopened link. A recorded-but-anonymised decline was rejected: the requester knows who they sent each link to, so any signal is joinable back to a person. |
| **Verification requires nobody** (d28) | No key material, no service, no lookup. Revocation: expiry first · a withdrawal is a **presented signed artifact**, never a service · an optional `withdrawalFeed` is an address **the requester controls**, never fetched by the verifier. |
| **No lookup surface** (d41) | The store has no `list`, `find` or query; the only way in is the capability secret. **Acceptances are never persisted by the kernel** — they are handed back to the caller, so "what has this counterparty signed" has nothing to answer with. |
| **No branding in the path** (d44) | The ceremony page names nobody, has no account, password, session, cookie or input. `FORBIDDEN_IN_CEREMONY_COPY` is a list in source and an assertion in the suite. |

## The counterparty with no device

One protocol, three renderings of the same bytes: a URL fragment (never sent to the host), a QR
payload, and a 26-character Crockford-base32 short code, dictatable over a voice call. Two delivery
modes producing **identical signed artifacts** — *hosted* (short code → the requester's own host) and
*carried* (the whole request travels as bytes; no server anywhere).

**An SMS/USSD/manual-relay path needs a transport, not a second protocol.** It is not built here — the
cost question is founder-terminal. A feature phone cannot hold a key, so that path is `delegated-mint`.

---

## Uplift note — the exact API surface a consumer takes

*(For the next venture session. `src/` in both packages is member-free; the consumer is named here.)*

**Duedale's DD-F4** adds the `Confirmation` record of `specs/flow-proof-platform.md` §2.1 — the
recipient-authored transition that `GrantActorClass.BENEFICIARY` declares and no code path writes. It
consumes exactly this, and **implements none of it locally** (d42):

```ts
// from "@kashscript/identity-server"  (≥ 0.2.0)
createCountersignRequest(input): Promise<CreatedCountersignRequest>
//   input:  { subject: DsseEnvelope, requesterDid, requesterPrivateKey, statement,
//             disclosures?, relationshipContext?, ttlSeconds?, withdrawalFeed?, nowSec? }
//   result: { request, requestId, capabilitySecretB32, compactB64u, linkFor(baseUrl) }

acceptCountersignRequest(input): Promise<AcceptCountersignRequestResult>
//   input:  { request, subject, signingKey, nowSec? }
//   ok:     { envelope /* subject + 2nd signature */, acceptance, countersignerDid }
//   not ok: REQUEST_EXPIRED | REQUEST_NOT_YET_VALID | SUBJECT_MISMATCH | ALREADY_COUNTERSIGNED

declineCountersignRequest(input?): { ok: true, recorded: false }
withdrawCountersignRequest({ request, requesterPrivateKey, nowSec? }): Promise<SignedCountersignWithdrawal>
claimCountersignKey({ priorDid, priorPrivateKey, successor, nowSec? }): Promise<CountersignKeyClaim>
assembleCountersignBundle({ subject, request, acceptances, withdrawal?, keyClaims? }): CountersignBundle

// the signing identity — one of these, never a key the platform minted for them
generateOneTimeSigningKey(): Promise<RelationshipSigningKey>                   // no wallet
deriveRelationshipSalt({ requesterDid, contextLabel }): Promise<string>
deriveRelationshipSigningKey({ masterSeed, relationshipSalt }): Promise<RelationshipSigningKey>
adoptDelegatedSigningKey({ publicKey, privateKey }): RelationshipSigningKey    // labelled not-subject-held

// delivery + the ceremony surface
encodeCrockford32(bytes) / decodeCrockford32(text)
decodeCompactCountersignRequest(compactB64u): SignedCountersignRequest
requestIdForCapability(secret): Promise<string>
renderCountersignPage(request, { requesterLabel, submitUrl, ceremonyModuleUrl, subject, localeCode?, dir? }): string

// hosted mode, on an IdentityServer instance
server.createCountersignRequest(input)
server.resolveCountersignRequest(capabilitySecretB32)   // the ONLY way in
server.markCountersignRequestAnswered(requestId)
server.withdrawCountersignRequest(request, requesterPrivateKey)

// from "@kashscript/attest"  (≥ 0.1.6) — verification, free
verifyCountersignBundle(bundle): Promise<CountersignVerifyReport>
isCountersignBundle(value): boolean
countersignRequestDigest(request): Promise<string>
COUNTERSIGN_BUNDLE_FORMAT, DST_COUNTERSIGN_REQUEST, DST_COUNTERSIGN_ACCEPTANCE,
DST_COUNTERSIGN_WITHDRAWAL, DST_KEY_CLAIM, type KeyCustody

// from "@kashscript/attest/succession"  (≥ 0.2.0-alpha.2, PL-2) — either path, any algorithm
signKeyClaim({ prior, successor, successorKeyCustody?, claimedAtUnix }): Promise<CountersignKeyClaim>
signHelperSet({ subject, helpers, need, sequence, issuedAtUnix, expiresAtUnix? }): Promise<SignedHelperSet>
draftHelperClaim / approveKeyClaim / withApprovals
verifyKeyClaim(claim): Promise<CountersignKeyClaimReport>          // also re-exported from ./countersign
verifySuccessionSet(claims, helperSets?): Promise<SuccessionSetReport>
```

**Three things a consumer must carry, not paraphrase.** (1) The report distinguishes a one-signature
claim from a two-signature proof — `twoSignatureProof` — and a surface may never present the first as
the second; an acceptance reported `independent: false` is the requester's own key and is never shown
as a countersignature. (2) `keyCustody` / `subjectHeldKey` travel with the record; a `delegated-mint`
or `unknown` custody is **not subject-held** and must be rendered as such. (3) Confirming must never be
a condition of being paid (d41: payment first, confirmation after), because declining has to stay free
— the mechanic makes declining costless, and a gate upstream of it would undo that. Every signer in the
report — `requesterDid`, `subjectVerifiedKeyids`, each `countersignerDid` — is the canonical `did:kash`
of the key it resolves to, so a consumer's own string comparisons compare keys.

## Changelog

| Version | Date | Change |
|---|---|---|
| **v1.2** | 2026-11-12 | **AU-3 (AUDIT-2026-11-11, A7-02, A7-04, A7-05).** Signers are counted and reported by the key a keyid resolves to, never by its spelling (`canonicalSignerOf`); each acceptance reports `independent`, and a bundle whose only verifying acceptance is the requester's own fails as `COUNTERSIGNER_IS_REQUESTER`; `requesterSignedSubject` is a fact, not a rule; custody is read exactly, `unknown` when unstated; the verifier returns a report for every input and throws nothing. Vectors: `test/vectors/au3`. `attest@0.2.0-alpha.9`. |
| **v1.1** | 2026-10-01 | **PL-2.** Key claims run across algorithms (Ed25519 ↔ P-256, the algorithm from each signer's `did:kash`), and gain a second path — the successor and a strict-majority helper quorum the prior key named in advance ([recovery.md](recovery.md)); prior-key claims are byte-identical. Claims in a bundle are verified together (a fork trusts neither). A P-256 countersigner verifies (DER on the envelope, `es256` on the acceptance). Dated note: wallets generate relationship keys; HKDF is server-side only. `attest@0.2.0-alpha.2`; identity-server unchanged. |
| **v1** | 2026-09-22 | Built. Four DSTs registered in attest; `kashscript-countersign/1` container + `verifyCountersignBundle`; a CLI branch that needs no `--key`; the ceremony, the per-relationship key derivation, withdrawal, key claim and the branding-free page in identity-server. `attest@0.1.6`, `identity-server@0.2.0` — **neither published**. |
