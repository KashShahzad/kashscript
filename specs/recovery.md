# Recovery by helpers — keys that survive a lost phone

**`specs/recovery.md` — v1 · 2026-10-01 · PL-2 · `@kashscript/attest/succession` (Apache-2.0) and `@kashscript/wallet`.**
Decisions: ECOSYSTEM d27.1, d41 (*separate identifiers per relationship*), d47(f) and (g), d28 · builds on [countersign](countersign.md) (the key claim), the [holder contract](holder-contract.md) (the export) and the [wallet](wallet.md) · ADR-0020.

> **What exists, and what does not.** The formats, the offline verifier and the wallet's three sides — the person, a helper, the new phone — are built and tested in source, including a full lost-phone run in the wallet's headless mode. **Nothing is published** (founder-terminal). Nothing here has run with a person or on a phone; the secure-chip code is written and not compiled here (PL-9).

## 1. The rule

**Recovery is by succession, never by copying (d47(g)(4)).** A key held in a phone's secure chip cannot leave it, and a person's keys are never on a server (d47(g)), so a lost phone cannot be restored — its keys are gone. What can be restored is **authority**: each place the person dealt with can be shown, offline, that a new key now speaks for the old one. Old records stay valid under the old keys, and nothing is re-signed.

A succession moves authority in one of two ways, both under the existing DST `kash-key-claim-v1`:

| Path | Who signs one body | When |
|---|---|---|
| **prior-key** | the old key and its successor | the old key is still there — a rotation, or a delegated-mint key claimed (ADR-0018) |
| **helpers** | the successor and a **strict majority** of the helper keys the old key named **in advance** | the old key is lost |

Both run across algorithms: **Ed25519 → P-256 and P-256 → Ed25519** (ADR-0020). Each key's algorithm comes from its own `did:kash`.

**A succession is not a takeover.** It needs the old key or the helper quorum, and the successor must sign too, so a claim can only name a key someone holds. **The platform is never a helper by default:** a wallet starts with no helpers, ships no key of anyone's, and only the person can add a helper. An organisation the person chooses is a helper like any other and counts as one.

## 2. The helper set — `kash-recovery-helpers-v1`

A Kash-Event (`kash-event` family, registered in `@kashscript/attest/dst` before anything signed under it), header `{"typ":"recovery-helpers","v":1}`, **signed by the key it protects**, before any loss:

| Field | Rule |
|---|---|
| `act` | `"name-helpers"` |
| `subjectDid` | the key these helpers may succeed — the signer |
| `helpers[]` | 2 to 16 distinct `did:kash` helper keys, never the subject. **Each place's key names different helper keys** (§4) |
| `need` | **at least 2**, and a **strict majority** of `helpers` (`need × 2 > helpers`). One key alone is a copy, not a quorum; a strict majority means any two quorums share a helper, so two successors claimed for one key always expose the helper who signed both |
| `sequence` | a positive integer. When the person replaces helpers, every set is re-signed with a higher one |
| `issuedAtUnix` | when it was signed |
| `expiresAtUnix` | `null`, or a time after `issuedAtUnix`. **The wallet writes `null`:** a set that lapsed silently would lock its holder out, the worse failure for an ordinary person. A replaced set is superseded instead (§3) |

The verifier enforces every rule above on any set it is shown, whoever wrote it. `signHelperSet` refuses to write one that breaks a rule.

## 3. The helper claim

The claim body is ADR-0018's (`act`, `priorDid`, `successorDid`, `successorKeyCustody`, `claimedAtUnix`) plus `by: "helpers"` and `helperSetSha256` — SHA-256 over JCS(`{header, body}`) of the set it rests on. Header `{"typ":"key-claim","v":1}`. It carries:

```jsonc
{
  "header": { "typ": "key-claim", "v": 1 },
  "body": { "act": "claim-key", "priorDid": "did:kash:…", "successorDid": "did:kash:Dn…",
            "successorKeyCustody": "subject-generated", "claimedAtUnix": 0,
            "by": "helpers", "helperSetSha256": "…" },
  "signatures": { "successor": { … }, "helpers": [ { "did": "did:kash:…", "signature": { … } } ] },
  "helperSet": { "header": { … }, "body": { … }, "signature": { … } }
}
```

Every signer signs the identical `{header, body}` under `kash-key-claim-v1`. A prior-key claim has no `by`, so it is **byte-identical to ADR-0018's**; a verifier older than PL-2 finds no prior signature on a helper claim and fails it — closed, not open.

**`verifyKeyClaim` (helper path), all offline:** the set verifies under its own `subjectDid` and keeps every §2 rule · it is for this `priorDid` · `helperSetSha256` matches it · the successor is not one of its helpers · `issuedAtUnix ≤ claimedAtUnix ≤ expiresAtUnix` · the successor's signature verifies · at least `need` **distinct** helper keys **named in the set** signed (a key not named, a repeat, the prior or the successor never counts). Reasons: `HELPER_SET_INVALID`, `HELPER_SET_NOT_FOR_PRIOR`, `HELPER_SET_MISMATCH`, `SUCCESSOR_IS_HELPER`, `OUTSIDE_HELPER_SET_WINDOW`, `SUCCESSOR_SIGNATURE_INVALID`, `BELOW_QUORUM`.

**`verifySuccessionSet`, over everything shown together:** two successors for one prior is a **conflict** — neither is trusted, and the report names any helper key that signed both. A helper claim whose set a newer presented set supersedes (same subject, higher `sequence`, issued before the claim) does not count. The report always says what offline checking cannot know: *absence of a conflicting claim is not proof none exists.*

**A limit of supersession (found 2026-10-06; reproduced; not decided).** "Issued before the claim" compares the newer set's `issuedAtUnix` with the claim's own `claimedAtUnix` — a time the claim's signers write themselves, with no witness. A quorum from a **replaced** set can therefore date its claim to before the newer set was issued, and `verifySuccessionSet`, shown **both** sets, reports `ok: true` and nothing superseded. Reproduced with helpers H1–H3 at sequence 1 replaced by H4–H6 at sequence 2 (as if H1 and H2 had been compromised): with an honest `claimedAtUnix` the old quorum's claim is superseded; dated between the two sets, it is not. A pinning test records this (`packages/attest/test/succession.test.ts`, "KNOWN LIMIT"). So replacing a helper set retires a stale quorum **only where a verifier can trust the claim's time**; offline, it cannot. The comparison is likely there so that a set issued *after* a succession cannot undo it — a thief of the old key could otherwise issue a higher-sequence set later — which makes this a trade between two attacks, not a slip: both need a trusted time. (That reason is inferred; it is not written down anywhere.) What could close it, none chosen: a witnessed time on the claim (attest already has Rekor and OpenTimestamps witnessing), or a rule that the successor and one helper from the newest set also sign. Until one is chosen, a place that has seen a helper set replaced should have the person confirm any claim resting on the old one.

## 4. Choosing helpers — how the person chooses, and what the wallet refuses

**The person chooses people, not accounts:** people they trust, who don't share a home or a phone with them, so one fire or one thief cannot take two. At least two must agree, and more than half of those chosen; the wallet's default is two of three, and three of five is better. Each helper adds themselves **from their own phone, in person**: the person shows an invitation, the helper's wallet answers with a pool of fresh keys made for this person alone.

| The wallet refuses | Why |
|---|---|
| fewer than two helpers, or `need` below two | one key alone is a copy, not a quorum |
| `need` that is not a strict majority | two separate groups could each claim the keys |
| a helper key that is one of the person's own | you cannot be your own helper |
| a key shared between two helpers | one key is one vote |
| an answer to another person's invitation | it names a different circle |
| a second enrolment from the same helper phone for the same person | the helper's wallet refuses it (the invitation carries a random circle name) |

**Honest limit, said to the person at the moment of choosing:** *keys are not people.* One person with two phones can enrol twice, and nothing cryptographic can tell. A quorum is only as independent as the people behind its keys.

**No helper key links two places (d41).** Each helper's pool holds 32 keys. Every place's key names a **different** key from every helper's pool, so two places shown a succession share no identifier. When a pool runs out, the next place stays **uncovered** — a pool key is never reused — and the wallet says so: *"N of your places aren't covered yet. Meet a helper to add more."* Helpers top up their pool when they next meet the person, and at every recovery.

## 5. What each party sees

| Party | Sees | Never sees |
|---|---|---|
| a helper | the six-digit code, how many places, the old and new keys and the other helpers' keys **for those places** | a record, a record id, a place, a name |
| a place | **its own** claim, when the person shows it | another place's claim, the person's helpers' other keys |
| the platform | nothing — it held no key, no record and no list of relationships | — |

A helper who colludes with a place can tell it the person recovered there: they signed the claim the place receives. Showing a succession to a place is the person's act, asked per place at next contact and never automatic — *linkage is something a subject does* (d41).

## 6. The wallet messages

Carried in person (a QR code) or by link — never through a server of ours. They are wallet-to-wallet messages, not kernel formats.

| Message | Carries |
|---|---|
| `kashscript-recovery-invite/1` | `circle` — a random name for this person's circle |
| `kashscript-recovery-enrolment/1` | `circle`, `keys[]` — a helper's fresh pool for this person |
| `kashscript-recovery-request/1` | `circle` (the new phone's), `claims[]` — drafted helper claims, each signed by its successor, with their sets. **No place labels** |
| `kashscript-recovery-approval/1` | `approvals[]` (`claimSha256`, `did`, `signature`), and a fresh `enrolment` for the new phone |

**The code.** Six digits from SHA-256 over the request's canonical bytes, shown on the new phone and on each helper's phone. The helper says yes **only after speaking to the person themselves and seeing the same code**.

**What the code is, and is not.** It ties the spoken check to this one request, so a mistake or a careless swap shows a different code. It is **not** proof against someone who can alter the request on its way to the helper: six digits is about 20 bits, and a substitute request naming a different successor key can be searched for until it shows the same code. Measured on 2026-10-06 — seven trials, a median of about 740,000 tries (roughly 30 seconds through WebCrypto on one laptop, the slowest way to do it) and 139 seconds at worst. (That a helper's wallet would accept the substitute is read from `Recovery.approve`, which checks `circle` only against circles the helper is already in; it was not run end to end.) Against an attacker who controls the channel between the new phone and a helper, the protection is carrying the request **in person** (a QR code), not the code. A longer code, or a commit step before the request is shown, would close this; it is **open** and nothing here decides it.

## 7. The new phone

1. **It needs the copy the person kept** — an export (or the account's encrypted backup, d47(f)). Records come back from it; so do the helper sets, each with the place it was for (holder contract v1.3, `recoveryHelpers`). *Without a saved copy, nothing comes back* — the wallet says so when helpers are chosen: *"Keep a copy of your records somewhere other than this phone. Helpers bring back your keys, not your records."*
2. For each place, a new key — **in the secure chip where there is one** (P-256, so an Ed25519 key is succeeded across algorithms) — and a claim drafted and signed by it.
3. Helpers answer. **One approval short of the quorum, nothing changes**; the approvals so far are kept.
4. With a quorum, each place moves to its new key; the claims are kept and exported; the helpers who came are chosen again, so the new keys are covered at once.
5. At the next visit, the person may show a place its claim. The place checks it offline (`verifySuccessionSet`) and carries its book on under the new key.

**Copies of a yes bound to a lost key**, and thank-yous bound to a lost relationship key, still verify as signed but **cannot be shown with holder binding** — the wallet never offers them. The issuer gives new ones; issuer-side re-issue on a presented succession is not built.

## 8. Conformance vectors

`packages/attest/test/vectors/es256/` (see its README): `succession-helpers.v1.json` (a 2-of-3 claim, Ed25519 → P-256), the cross-algorithm prior-key claims in `countersign-es256.v1.json`, an export carrying both kinds and a `recoveryHelpers` entry, and negatives (below quorum, a set its key did not sign, a fork). Generated once and never regenerated.

## Changelog

| Version | Date | Change |
|---|---|---|
| **v1 (limit recorded)** | 2026-10-06 | **A limit of supersession written down (§3).** A quorum from a replaced helper set can backdate its claim to before the newer set and is not retired, even when the verifier is shown both sets; reproduced and pinned by a test. Not a format change; what would close it is open. |
| **v1 (correction)** | 2026-10-06 | **The code's claim corrected (d11).** §6 said a request changed in transit shows a different code. Six digits is about 20 bits and can be searched for, so the sentence now says what the code is and is not, and that the in-person route is the protection against an attacker on the channel. No format, code or vector changed; a longer code or a commit step is open. |
| **v1** | 2026-10-01 | **Recovery by helpers (PL-2).** `kash-recovery-helpers-v1` registered first; the helper claim on `kash-key-claim-v1`; strict-majority quorums of at least two; per-place helper keys from 32-key pools; conflict and supersession across a presented set; the wallet's invite, enrolment, request and approval with a six-digit code; the new phone's flow. |
