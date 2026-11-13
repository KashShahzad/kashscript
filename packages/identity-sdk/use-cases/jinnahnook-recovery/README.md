# Jinnahnook identity recovery — M-of-N advisor quorum

Cross-persona flagship for `@kashscript/identity-sdk` (and a real
sovereignty primitive every persona benefits from). Demonstrates
M-of-N social recovery using identity-core's Ed25519 primitives —
no React, no browser, headless crypto.

## Scenario

> A PhD student loses their laptop a week before their thesis
> defense. The private key is gone (Ed25519 is non-recoverable by
> design). What survives is the student's DID + a recovery-quorum
> envelope they signed at enrolment, naming three advisors. Two
> advisors collectively sign a recovery claim that binds the
> student's NEW pubkey to the original DID. Verifiers who trust the
> quorum's set update their records — the student's defense goes
> ahead.

## Flow

1. **Enrolment** — student signs a `set-recovery-quorum` envelope
   listing M-of-N advisor DIDs + pubkeys, under DST
   `kash-recovery-v1\n`.
2. **Loss** — student's device + key are gone.
3. **New device** — student generates a fresh Ed25519 keypair.
4. **Recovery claim** — student (or anyone) builds an unsigned
   `recovery-claim` body referencing the original DID + new pubkey.
5. **Attestation** — each advisor independently signs the claim under
   the same DST.
6. **Verification** — anyone holding the quorum envelope + ≥M
   attestations + the student's original pubkey verifies via
   `verifyRecovery(...)`.

## Five layers tested

1. Enrolment invariants (strict-majority threshold required)
2. Claim construction
3. Happy path — 2-of-3 + over-quorum
4. Under-quorum rejection
5. Adversarial: duplicate attestations, outsider signers, divergent
   claim bodies, forged quorum envelopes

## Test result

```
10 pass · 0 fail · 20 expect() calls
```

## Files

- `fixture/integration.test.ts` — 10 tests across 5 layers

> **Promoted upstream**: the recovery primitives — `setRecoveryQuorum`,
> `buildRecoveryClaim`, `advisorAttestRecovery`, `verifyRecovery`,
> `advisorRefFromSigner` — were promoted from this fixture into
> `@kashscript/identity-sdk/recovery`. The use-case test now consumes
> the published API directly:
>
> ```ts
> import {
>   setRecoveryQuorum, buildRecoveryClaim,
>   advisorAttestRecovery, verifyRecovery,
> } from "@kashscript/identity-sdk/recovery";
> ```
>
> Headless callers (Node, Bun, edge runtimes, audit tools) can run the
> full M-of-N quorum-verify flow without a browser. The React-side
> `recover()` on `KashAuthProvider` is the UI layer above these
> primitives.
