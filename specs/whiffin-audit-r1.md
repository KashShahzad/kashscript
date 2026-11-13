# `@kashscript/whiffin` — Red-Team Audit (Round 1)
**`specs/whiffin-audit-r1.md`**

> **Auditor scope:** the full `packages/whiffin/src` tree (mandate lifecycle, policy gate, W3C-VC/AP2
> credential layer, rails raast/emvco/safepay/softpos, partner-ledger + simulation, the every-rupee report)
> + the `identity-core`/`identity-zkp` primitives — traced money-path byte-by-byte (M6, ADR-0016).
> **Outcome:** 8 findings (2 High, 3 Medium, 3 Low). 4 fixed this round (F3, F5, F6, F7); F1, F2, F4, F8
> logged (settlement is venture-side per ADR-0016 — flagged as the top items).
> **Severity scale:** *High* = money loss enabler · *Medium* = signature/binding gap · *Low* = rails
> correctness / reconciliation-overstatement.

This package **moves money**, so single-process replay + domain separation were scrutinized hardest — both
are solid. The two High items are *coupling* gaps: the payout is not bound to the atomic nonce burn, and no
amount is validated — both of which the settlement layer (venture-side) must close.

---

## Part I — Findings

### F1 — Payout is not coupled to the atomic nonce burn · **High** · DESIGN-GAP · LOGGED (+FLAG)
- **The hole:** `redeemGrant` burns the single-use nonce and returns `{record}` — but the actual money
  movement (`PartnerLedgerRail.settle`, receipt emission) is the caller's job **outside** the nonce-guarded
  region. The nonce guarantees the REDEEMED *row* is written once, not that the fiat moved once.
- **Disposition — LOGGED + FLAGGED.** Settlement is intentionally venture-side (ADR-0016). **Patch direction:**
  either have `redeemGrant` own the settlement inside the burn-guarded region (burn → settle → mark REDEEMED,
  with a documented compensation path), or document loudly that callers MUST settle *after* `redeemGrant`
  resolves and MUST NOT settle a grant whose `redeemGrant` threw `NONCE_SPENT`. **Top finding.**

### F2 — No settlement-amount validation; simulation `settle` ignores the amount · **High** · DESIGN-GAP · LOGGED
- **The hole:** `RedeemRequest` carries no amount; `redeemGrant` never reads `grant.amountPaisa` (a *max*),
  and `SimulationPartnerLedger.settle` ignores `amountPaisa` and always returns `ok:true`. The report then
  attributes the **full** grant amount regardless of what settled.
- **Disposition — LOGGED.** **Patch direction:** add `settlementAmountPaisa` to `RedeemRequest`, assert
  `0 < amount <= grant.amountPaisa` as an ordered policy check *before* the burn, and thread that amount (not
  `grant.amountPaisa`) into both `settle` and the report's `redeemedPaisa`. (API change — coordinate with the
  venture consumer.)

### F3 — DST not pinned in `verifyGrant` / credential verify · **Medium** · CODE-BUG · **FIXED r1**
- **The hole:** `verifyGrant` verified under the signature's **own** `dst` (attacker-controlled wire data),
  not asserting `=== GRANT_DST`; the credential's advertised `domainSeparationTag` was decorative.
- **Fix:** `verifyGrant` now rejects unless `signed.signature.dst === GRANT_DST` before verifying. Regression
  test: "accepts a genuine grant but rejects one whose signature DST is swapped." (Credential-proof DST
  assertion logged as the same-shaped follow-up.)

### F4 — Redeem is allowed directly from `ISSUED` (delivery unenforced) · **Medium** · DESIGN-GAP · LOGGED
- **The hole:** the redeem guard is a **denylist** (`REDEEMED/SETTLED/…`); `ISSUED` is not blocked, so an
  undelivered voucher can be spent. `SMS_OTP`/`PASSKEY` binding rules are declared but never enforced (only
  `BENEFICIARY_DID` string-equality is checked).
- **Disposition — LOGGED.** **Patch direction:** make the guard an **allowlist** (redeem only from
  `DELIVERED`, or `ISSUED` only under a no-delivery `BindingRule`), and enforce the declared `BindingRule`.

### F5 — `verifyVendorInclusion` accepted an unbounded proof depth · **Medium** · DESIGN-GAP · **FIXED r1**
- **The hole:** `recoverRoot` walked any-length `siblings`/`positions`; no depth bound (second-preimage-hard,
  but a structural guardrail gap + a cheap async-hash-per-level DoS).
- **Fix:** `verifyVendorInclusion` now rejects a proof with `siblings.length > 32` (2^32 leaves ≫ any real
  allowlist). Regression test added. (The load-bearing leaf/internal DST separation in identity-zkp is
  correct and untouched.)

### F6 — EMVCo amount had no upper bound (precision loss > 2^53) · **Low** · CODE-BUG · **FIXED r1**
- **The hole:** `formatAmountCentsForEmv` guarded finite/integer/≥0 but not `<= MAX_SAFE_INTEGER`; above
  2^53 the integer/minor split silently misprints the amount.
- **Fix:** reject `amountCents > Number.MAX_SAFE_INTEGER`. Regression test added.

### F7 — CRC-16 + tag length computed over UTF-16 code units, not UTF-8 bytes · **Low** · CODE-BUG · **FIXED r1**
- **The hole:** `computeCrc16CcittFalse` did `charCodeAt(i) & 0xff` and `emvTag` used `value.length` — for a
  non-Latin-1 merchant name the CRC + length prefix disagreed with any spec-correct EMVCo reader.
- **Fix:** CRC over `TextEncoder().encode(input)` bytes; `emvTag` length counts UTF-8 bytes. Identical output
  for ASCII (verified against the CRC-16/CCITT-FALSE check value `0x29B1` for `"123456789"`). Regression test
  covers the multi-byte tag length.

### F8 — Reconciliation "invariant" is a tautology; settled fiat unchecked · **Low** · DESIGN-GAP · LOGGED
- **The hole:** `issuedPaisa === redeemedPaisa + unspentPaisa` holds by construction (`unspentPaisa` is
  *defined* as the difference), so it cannot detect a discrepancy; `settledPaisa`/`refundedPaisa` are injected
  and never cross-checked.
- **Disposition — LOGGED.** **Patch direction:** add real invariants that can fail (`settledPaisa <=
  redeemedPaisa`, `refundedPaisa <= unspentPaisa`) inside the signed bytes; reword the header so "invariant"
  isn't overstated as a check.

---

## Part II — Disposition Summary

| Finding | Severity | Disposition |
|---|---|---|
| F1 payout ↮ nonce burn | High | LOGGED + FLAG (settlement coupling — venture-side) |
| F2 no amount validation | High | LOGGED + FLAG (add settlementAmountPaisa) |
| F3 DST not pinned | Medium | **FIXED r1** (assert GRANT_DST) + test |
| F4 redeem-from-ISSUED | Medium | LOGGED (allowlist DELIVERED; enforce BindingRule) |
| F5 unbounded merkle proof | Medium | **FIXED r1** (cap ≤32) + test |
| F6 EMVCo amount overflow | Low | **FIXED r1** (reject unsafe int) + test |
| F7 CRC/length UTF-16 | Low | **FIXED r1** (UTF-8 bytes) + test |
| F8 reconciliation tautology | Low | LOGGED (real invariants) |

## Part III — What the package gets right
- **Replay / double-spend (single-process) — solid.** The nonce burns *after* every pure check passes; a
  failed check can't consume it; the redeemable-state denylist + `NonceStore.burn`-once contract block
  same-record replay (the atomicity gap is only under a *distributed* store + the payout coupling, F1/F2).
- **Signature domain separation (bytes) — solid.** Distinct DSTs per grant/cart/report; the header binds
  `grantId`/`reportId`; the RFC-8785 canonicalizer is hardened. (The residual was DST *pinning* — F3, fixed.)
- **Merkle leaf/internal separation — solid.** `LEAF_DST` vs `INTERNAL_DST` + length-prefixed leaves kill
  the leaf-as-internal second-preimage; the allowlist de-dupes+sorts and rejects empty sets.
- **Safepay HMAC / Raast — solid.** Constant-time compares, strict format gates, timestamp tolerance closing
  replay, hash-then-compare so lengths never leak.
- **SIMULATION labelling — solid within the package.** `SimulationPartnerLedger` stamps `simulation:true`
  everywhere and the report folds it inside the signed bytes.

## Part IV — Residual Risks Carried Forward
- **F1/F2 (settlement coupling + amount)** are the real money-loss enablers and are **venture-side** — they
  must be closed in the duedale-angel swap (the report + terminal flows), not in the protocol alone.
- **F4 delivery/binding enforcement** — until the guard is an allowlist, an operator-visible undelivered
  grant is spendable.

---
**End of Round 1.** F3/F5/F6/F7 fixed with tests this session; F1/F2/F4/F8 carried with patch directions
(F1/F2 flagged for the venture settlement swap).
