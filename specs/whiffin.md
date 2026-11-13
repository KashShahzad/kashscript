# `@kashscript/whiffin` — the Settlement Protocol (rail-agnostic)

> **Superseded in part — 2026-10-09 (KS-R4, ecosystem d59).** Whiffin is now **the mandate protocol: it never moves money**, and its licence is **Apache-2.0 from 0.2.1** (the header below says Commercial; that was true of 0.1).
> 0.2.0 removed every settlement path and every rail adapter (the EMVCo/Raast/Safepay/SoftPOS adapters, the partner-ledger and
> chain rails), the lifecycle states `SETTLED`/`REFUNDED`/`CLAWED_BACK`, the report's settled/refunded totals, and
> `SegmentPolicy`'s settlement and compliance profiles. Rails survive as **names** a declaration can cite. A mandate now carries its
> purpose, its limits, a required end date (d43) and an arrival clause — the recipient confirms, two signatures (d41). Read the rest
> of this file as the **0.1 record**; `packages/whiffin/README.md` is the current contract. The text below is left as written.

**`specs/whiffin.md` — v0.1 · BUILT in M4 · red-team audited round 1 (M6). Commercial (SSLA Schedule B).**

> **Security:** [`whiffin-audit-r1.md`](whiffin-audit-r1.md). Fixed this round: F3 (grant DST not pinned),
> F5 (unbounded merkle proof depth), F6/F7 (EMVCo amount overflow + UTF-8 CRC/length). **Flagged for the
> venture settlement swap** (venture-side per ADR-0016): F1 (payout not coupled to the atomic nonce burn) +
> F2 (no settlement-amount validation) — the two real money-loss enablers; F4 (redeem-from-ISSUED) + F8
> (reconciliation tautology) logged.

> Status: **draft — built, consumer-acceptance pending.** The package is implemented and its own test
> suite is green (M4, [ADR-0016](../docs/adr/0016-protocol-manifestation.md)), but per the
> consumer-as-acceptance rule the API stays `0.x` until duedale-angel's terminal + `/report` flow
> consume the published package with the ported report tests green. Every API is **derived from the
> Duedale seeds**; the W3C VC / AP2 layer is **web-verified**, not invented. **Licence: Commercial
> (SSLA Schedule B).**

## Purpose

Rail-agnostic settlement: purpose-bound **mandates** + signed **receipts** that settle over **whatever
rail fits** — chain is **one optional rail, never a requirement** (ECOSYSTEM). Where money moves,
ventures consume Whiffin and never reach for raw `trade-sdk` (ECOSYSTEM decision 12). Fourth in the
publish order (`attest → identity-server → muffler → whiffin → hudhud`). Depends on
`@kashscript/identity-core` (Kash-Event signing), `@kashscript/identity-zkp` (`/merkle` — the Apache
vendor-allowlist layer), and `@kashscript/attest` (report chain + the `kash-report-v1` DST registry).

## Seeds (the API oracles — M4 derives from these)

- **Duedale `duedale-core/grant` + `ks-adapters/{issue,redeem,grant,report}`** — the grant lifecycle,
  the redeem policy gate, grant signing, and the every-rupee report (incl. its **9-test behaviour suite**).
- **Duedale `duedale-core/program`** — the `SegmentPolicy` / `Program` policy-blind types.
- **Duedale `whiffin-gateway-sdk/{gateways,terminal}.ts`** — the Raast / EMVCo / Safepay / SoftPOS rails.
- **W3C Verifiable Credentials Data Model 2.0 + AP2 (Agent Payments Protocol) mandates** — the mandate
  credential shape (web-verified).

## Mandate core — W3C VCs with AP2 semantics

A purpose-bound **grant** IS an AP2 **Intent Mandate** (human-not-present, pre-authorized conditions):
a fixed max amount, a purpose lock, an allowed-vendor set (Merkle root), an expiry/TTL, and a single-use
nonce. Offer→receipt→dispute maps to the AP2 **Cart Mandate**.

### The credential (`credential.ts`)

`toMandateCredential(signedGrant, {issuer})` → a W3C VC 2.0:

| Field | Value |
|---|---|
| `@context` | `["https://www.w3.org/ns/credentials/v2", "https://kashscript.com/ns/mandate/v1"]` |
| `type` | `["VerifiableCredential", "MandateCredential", "IntentMandate"]` |
| `issuer` | the operator `did:kash` that signed the grant |
| `validFrom` / `validUntil` | ISO 8601 (issue time / grant expiry) |
| `credentialSubject` | AP2 Intent Mandate: `{ id: beneficiary, purpose, funder, constraints: { maxAmountPaisa, currency, allowedVendorsRoot, expiry, singleUseNonce } }` |
| `proof` | `{ type:"KashEventSignature2026", cryptosuite:"ed25519-jcs-2026", verificationMethod, domainSeparationTag:"kash-grant-v1\n", proofValue: <the Kash-Event Ed25519 signature> }` |

The proof **embeds the existing `kash-grant-v1` Ed25519 signature** — no new crypto (AP2 mandates sign
"P-256 or stronger"; Ed25519 qualifies). `verifyMandateCredential(vc, publicKey)` reconstructs the
grant losslessly from the subject and verifies its Kash-Event signature. Cart mandates
(`forgeCartMandate` / `toCartMandateCredential`) verify the same way under `kash-cart-v1`.

### Lifecycle + policy gate (`mandate/` + `policy.ts`)

`issueGrant` · `markDelivered` · `redeemGrant`, over injectable `GrantLedger` + `NonceStore` interfaces
(+ InMemory reference impls). The **config-driven policy gate** is an ordered set of named `PolicyCheck`s
— `signature · beneficiaryBinding · purposeMatch · notExpired · vendorInclusion` — run in fixed order,
with the single-use nonce burned **LAST** (atomic) so a failed check never consumes a voucher. **Zero
segment branching**: the gate reads grant + request FIELDS only, never `segmentTag`. Every rejection is
a neutral `WhiffinPolicyError` code (`PURPOSE_MISMATCH` / `EXPIRED` / `NONCE_SPENT` /
`VENDOR_NOT_IN_ALLOWLIST` / `BENEFICIARY_BINDING_FAILED` / `SIGNATURE_INVALID` / `NOT_FOUND` /
`NOT_REDEEMABLE` / `VALIDATION`) — the `DD_*` mapping stays venture-side.

## Rails (`rails/`)

| Rail | Surface |
|---|---|
| `emvco` | MPM v01 tag encoder + SBP-profile tag-26 + amount formatter + **CRC-16/CCITT-FALSE** + `compileEmvcoMpmQr`. Pure. |
| `raast` | `verifyRaastIngressSecret` (constant-time shared-secret) + `emitRaastP2mQr` (P2M QR via emvco). |
| `safepay` | `verifySafepayHmacSignature` + `computeSafepayHmacSignatureHex` (WebCrypto HMAC-SHA256, constant-time). |
| `softpos` | `loadSoftposBridge` (SRI-pinned, browser-gated) + `parseCheckinQrScan` + `assertReaderReady`. |
| `partner-ledger` | `PartnerLedgerRail` interface + `SimulationPartnerLedger` — **every result labelled `simulation: true`**. SIMULATION labelling lives here. |
| `chain` | `ChainSettlementRail` interface + `notWiredChainRail()` stub. The EVM/Solana impl is venture-wired via `trade-sdk` (artifacts guard — whiffin never builds contracts, no trade-sdk dep). |

## Reconciliation (`report/`)

The every-rupee-style report: a **pure projection** (`buildReconciliationReport` — per-grant lifecycle,
vendor breakdown, totals; reconciliation invariant `issuedPaisa === redeemedPaisa + unspentPaisa`) + a
**render-time hash-chain** (`computeChainSummary` — `rowHash=SHA-256(utf8(prevHex)‖JCS(row))`, on attest's
`sha256Hex`) + a **signed envelope** (`signReport` / `assembleSignedReport` under `kash-report-v1`).
Generalized: `simulation` / `settledPaisa` / `refundedPaisa` / `disclaimers` / envelope-`typ` /
`genesisLabel` are **injected** (honest defaults). Passing the Duedale-branded envelope type + genesis
yields a report that **re-verifies under attest's M1 `verifyDuedaleReport`** — the "on attest envelopes"
link. Compat aliases `EveryRupeeReport` / `buildEveryRupeeReport` for a drop-in venture swap.

## Standards conformance

W3C Verifiable Credentials Data Model 2.0 + AP2 (Intent / Cart) mandate semantics; receipts anchored via
`@kashscript/attest` (`kash-report-v1`, RFC 8785 JCS + Ed25519). Rails are adapters; crypto is one
optional rail. EMVCo MPM v01 + CRC-16/CCITT-FALSE; SBP Raast P2M profile.

## Stays venture-side (guard b, ADR-0016)

`SegmentPolicy` CONTENT + `DEMO_PROGRAMS` fixtures; the `DD_*` error envelope mapping; funder/vendor UI;
the demo's SIMULATION posture (passed as report config); the concrete SoftPOS provider scripts; the
trade-sdk-backed chain-rail impl.

## Done when

1. Rails + mandate + policy + credential (VC/AP2) + the **9 ported report tests** + the **attest
   round-trip** green (38 tests). ✅
2. `typecheck` + `check-boundary.ts` (whiffin COMMERCIAL) + full-workspace typecheck green. ✅
3. **Venture-side follow-up (post-publish):** duedale-angel's terminal + `/report` swap onto the
   published package (neutral errors → `DD_*`, `DEMO_PROGRAMS` supplied venture-side); Duedale ROADMAP
   P2.1/P2.3 close as satisfied-by-manifestation (consumer-as-acceptance closes M4).
4. **Deferred to M6 (ROADMAP M6.3):** the runtime `assertWhiffinLicense` paywall + kash-registry tier mapping.

## Change Log

| Version | Date | Summary |
|---|---|---|
| **v0.2** | 2026-10-09 | KS-R4 (d59): the mandate protocol. Removed every settle path and rail adapter (rail names kept as an enum); narrowed the lifecycle to ISSUED · DELIVERED · REDEEMED · EXPIRED; dropped the report's settled/refunded totals and `SegmentPolicy`'s settlement + compliance profiles; added the arrival clause (`recipient`, 2 signatures) and a verified `validUntil`. 0.1 artifacts still verify. |
| **v0.1 · audit r1** | 2026-07-05 | Round-1 red-team audit (M6): F3 (pin the grant DST), F5 (bound the merkle proof depth), F6/F7 (EMVCo amount overflow + UTF-8 CRC/tag length) fixed inline; F1/F2 (payout↮nonce-burn coupling + amount validation) flagged for the venture settlement swap; F4/F8 logged. 42 tests green. See [`whiffin-audit-r1.md`](whiffin-audit-r1.md). |
| **v0.1** | 2026-07-05 | Built in M4 (ROADMAP Manifestation). Ported the grant lifecycle + config-driven policy gate + every-rupee report (9-test suite) + the Raast/EMVCo/Safepay/SoftPOS rails from the Duedale seeds; added the net-new W3C VC / AP2 mandate credential layer (web-verified), the partner-ledger SIMULATION rail, and the optional chain-rail interface. A whiffin report re-verifies under attest's `verifyDuedaleReport`. 38 tests green. First Commercial protocol (SSLA Schedule B). API stays `0.x` pending the duedale-angel consumer swap. |
| **v0.0** | 2026-07-05 | DRAFT skeleton created in M0. |
