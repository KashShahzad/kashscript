# Paceplug co-founder multi-sig identity

Startup-persona flagship for `@kashscript/identity-sdk`. Demonstrates
how a company-level DID can be authoritatively owned by an M-of-N
co-founder quorum rather than a single key.

## Scenario

> A three-co-founder startup constitutes a 2-of-3 quorum over the
> company's DID. Every board-level action (equity grants, banking
> changes, hiring) is a Kash-Event each founder independently signs
> under DST `kash-multisig-v1\n`. The action is "authorised by the
> company" iff M distinct founder signatures verify against the body.

## Construction

Same shape as the M-of-N social recovery in `jinnahnook-recovery` —
both are quorum attestations over a shared body. The difference is
semantic:
- Recovery rotates the canonical key.
- Multi-sig company DIDs authorise per-action decisions.

The constitution envelope captures the founder set + threshold; future
verifications resolve against that constitution.

## What this proves

- Constitution refuses non-strict-majority thresholds at build time.
- A 2-of-3 quorum verifies under `verifyBoardAction`.
- Adversarial cases all reject with stable typed reasons:
  - under-quorum (only 1 of 3)
  - duplicate same-founder signatures
  - outsider co-signs (not in the founder set)
  - founder signs a different body than the proposed action

## Test result

```
8 pass · 0 fail · 15 expect() calls
```

## Files

- `fixture/multisig.ts` — `buildConstitution`, `founderCoSign`,
  `verifyBoardAction`, `founderRefFromSigner`
- `fixture/integration.test.ts` — 8 tests across 3 layers
