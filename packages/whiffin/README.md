# @kashscript/whiffin — the mandate protocol

**Purpose-bound mandates (W3C VC, AP2 semantics). It never moves money.** Apache-2.0 from 0.2.1.

A mandate is a deed in code: *this value is dedicated to this purpose, within these limits, until this date — and arrival is confirmed by the recipient.* Whiffin writes and signs that. The payer then pays **on their own rail**, the recipient confirms **it arrived**, and Duedale proves the money reached the right hands within the mandate:

`DECLARE` (whiffin) → `PAY` (the payer's own rail) → `CONFIRM` (the recipient, two signatures) → `RECONCILE`

Nothing here calls a rail, holds a balance, or marks a payment done on its own say. A test (`test/never-moves-money.test.ts`) keeps the source free of settle paths, custody words and network calls.

Built in phase **M4** of the protocol Manifestation ([ADR-0016](../../docs/adr/0016-protocol-manifestation.md)); 0.2.0 is the KS-R4 realignment of d59. Depends on [`@kashscript/identity-core`](../identity-core), [`@kashscript/identity-zkp`](../identity-zkp) (`/merkle`, until KS-R6 re-points it) and [`@kashscript/attest`](../attest).

## What a mandate carries

| It carries | Where | Rule |
|---|---|---|
| its **purpose** | `purposeTag`, from the program's closed list | the payer's declared purpose |
| its **limits** | a fixed `amountPaisa` and an approved-vendor Merkle root | bound to a delegate spending money that is not theirs |
| a **required end date** | `expiryUnix` (and the VC's `validUntil`, which must match it) | d43: every rule expires |
| **who confirms arrival** | `arrival: { confirmedBy: "RECIPIENT", signatures: 2 }` | d41: two signatures or it is not proof |

`issueGrant` always writes the end date and the arrival clause. `signatures` is the literal `2`, so a one-signature mandate cannot be expressed, and `confirmedBy` is a role, never a DID — a mandate names no one new, and cannot become a list of who has not confirmed.

```ts
import { issueGrant, markDelivered, InMemoryGrantLedger } from "@kashscript/whiffin/mandate";
import { toMandateCredential, verifyMandateCredential } from "@kashscript/whiffin/credential";

const { signed } = await issueGrant(req, program, operatorPriv, ledger);
const vc = toMandateCredential(signed, { issuer: operatorDid });   // W3C VC 2.0 + AP2 Intent Mandate
await verifyMandateCredential(vc, operatorPub);                    // proof = the kash-grant-v1 signature
```

- **Lifecycle** — `issueGrant` · `markDelivered` · `redeemGrant`: `ISSUED → DELIVERED → REDEEMED`, or `EXPIRED`. Those four are the whole vocabulary.
- **Policy gate** (`./policy`) — an ordered set of named checks (signature · binding · purpose · expiry · vendor Merkle inclusion), nonce burned last. **Use it to bound a delegate** (a trustee, a treasurer, a procurement officer, an AI agent). Pointed at a recipient it would be a restriction on what a person buys with money they received — d41's never-build list. A DID is not a secret, so the default binding check is `@deprecated` as a security boundary.
- **Credential** (`./credential`) — Intent Mandate and Cart Mandate as W3C VCs. The proof embeds the Kash-Event Ed25519 signature; the verifier also checks that `validUntil` and the arrival clause agree with what was signed.
- **Report** (`./report`) — a reconciliation report: a pure projection (per-mandate lifecycle · vendor breakdown · counts), a render-time SHA-256/JCS hash-chain, and a `kash-report-v1`-signed envelope that re-verifies under attest's `verifyDuedaleReport`. It counts mandates; it holds no figure for value paid or returned.
- **Rails** (`./rails`) — **names only**: `RAAST · EMVCO · SAFEPAY · SOFTPOS · CHAIN`, for a declaration to cite. No adapter, no dispatch.

## What 0.2.0 removed (from 0.1.0)

- every settle path: the partner ledger, the on-chain rail, the report's settled and refunded totals;
- every rail adapter: EMVCo/Raast QR, the Raast and Safepay verifiers, the SoftPOS bridge (all in git history);
- the lifecycle states `SETTLED`, `REFUNDED`, `CLAWED_BACK`;
- `SegmentPolicy.settlementProfile` and `complianceProfile` (custody and AML apparatus; declared and never read).

**Still verifies:** grants, credentials and reports signed under 0.1.0. Signatures are checked over each artifact's own JSON, never against these types, and a grant with no arrival clause verifies byte for byte. The wire labels (`kash-grant-v1`, `kash-report-v1`, `kash-cart-v1`, the header `typ`s, the default chain genesis) and the `GrantActorClass` values did not change.

## Status

`0.x`. A consumer that builds `SegmentPolicy` records must stop setting the two removed profiles, and one that stores grants field by field must also store `arrival`, or it cannot re-verify a 0.2.0 grant from its own database. Duedale's `toWhiffinProgram` cast can then be deleted.

Apache-2.0; see `LICENSE`. Versions 0.1.0 and 0.2.0 were published under SSLA Schedule B and keep those terms; the licence changed because the package no longer moves money (`docs/legal/license-matrix.md`, footnote 5).
