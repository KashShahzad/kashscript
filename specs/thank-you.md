# The thank-you — a promise, never a balance

**`specs/thank-you.md` — v1 · 2026-09-25 · PL-3 · verification in `@kashscript/attest/exchange` (Apache-2.0) · vct `https://kashscript.com/vct/thank-you/1`, owner `indorania` (d49(c)).**
Decisions: ECOSYSTEM d41, d49 · builds on [presentation](presentation.md) and [the holder contract](holder-contract.md).

> **What exists, and what does not.** The format and its verifier are built in attest source (`0.2.0-alpha.1`), with vectors, and **unpublished**. No issuer gives one, no wallet holds one, and **the stored-value and gift-card legal reading is owed before any real use** (d49 rule 7).

## 0. What it is

With proof on, the counterparty may give the actor a **thank-you**: a non-transferable, signed voucher the wallet holds and the actor redeems with whoever gave it (d49(b)). It is an SD-JWT VC, `typ: dc+sd-jwt`, `alg: EdDSA` — or `ES256` since PL-2, as the issuer's key decides; its holder key may be P-256.

| Claim | Meaning |
|---|---|
| `iss` | the counterparty that gives it — an establishment, or a verifier running a programme of asks. **Never Indorania or a member** (rule 2) |
| `cnf.jwk` | the holder's relationship key — the only key that can redeem it |
| `for` | `{act: "answered-ask", ask}` or `{act: "confirmed-session", session}` — **the answering, never the answer** (rule 1) |
| `value` | **text**, in plain words: "a free cup of tea on your next visit" |
| `redeemAt` | where, in plain words or the issuer's own address |
| `exp` | when it lapses |
| `credentialStatus` | a redemption index in the issuer's status list — a set bit reads *used or withdrawn* |
| `iat` | rounded to the day |

## 1. Nothing adds up

**No field lets anything sum thank-yous into a balance or a score** (d49; *no points, tiers, balances or leaderboards*). A verifier refuses a voucher carrying, at any depth, `amount`, `balance`, `total`, `sum`, `points`, `score`, `count`, `credits`, `currency`, `rank`, `tier`, `level`, `transfer`, `transferable` or `bearer` (`BALANCE_FIELD`). It also refuses one carrying the answer — `answer`, `outcome`, `result`, `verdict`, `confirmed`, `disputed` (`ANSWER_CARRIED`). The value is text, so there is no number to add.

## 2. It cannot move

**Redeeming is presenting it to its own issuer** over OID4VP, with a KB-JWT from the key in `cnf`, `aud` = the issuer. Whoever else holds the string cannot sign that. A presentation to anyone but the issuer fails (`REDEEMED_ELSEWHERE`). After honouring it, the issuer sets its bit, and a second redemption fails (`USED_OR_WITHDRAWN`). There is **no transfer path**: no field, flow or endpoint re-binds a voucher to another key.

## 3. The issuer's rules — policy, stated here, enforced where issuing happens (PL-8)

attest can check the voucher's bytes, not its issuer's conduct. The issuer must follow all seven of d49's rules:

1. **Reward the answering, never the answer.** Confirming or disputing earn the same.
2. **The counterparty issues it** — never Indorania or a member. The platform funds nothing and holds no value.
3. **A promise, not a balance.** The value stays with the issuer and is redeemed on the issuer's own rails.
4. **Declining costs only the thank-you.** No service is withheld (d27.3).
5. **Only countersigned records earn one** — a complete session or an answered ask, never a pending session or a device-asserted record like IGEO1. Capped per relationship per period.
6. **Never from a giver with both power and sight** — power over the actor's pay, work, aid, access or standing, *and* sight of everyone who could have answered. Until an unlinkable pool exists and passes the simulation, this is absolute.
7. **Plain words, and the law first** — *thank-you* or *voucher*, never *gift card*; the legal reading comes before any real use.

## Changelog

| Version | Date | Change |
|---|---|---|
| **v1.1** | 2026-10-01 | Additive (PL-2): a thank-you may be signed ES256 and bound to a P-256 holder key; the key decides the algorithm. |
| **v1** | 2026-09-25 | The voucher as an SD-JWT VC: text value, holder-bound, redeemed only with its issuer, a redemption index, no summable or answer-carrying field. Verification in attest `0.2.0-alpha.1`, with vectors — **unpublished**. |
