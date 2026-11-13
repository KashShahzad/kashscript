# Age-proof — identity-zkp selective disclosure

Student-persona flagship for `@kashscript/identity-zkp`. First demonstration
of the selective-disclosure (Merkle-commitment) primitive end-to-end.

## Scenario

> A university registrar issues a student-ID envelope committing to
> five fields (legalName, dateOfBirth, cnic, citizenship, isOver18).
> When the student wants to borrow from the adult-only library
> section, they create a disclosure that reveals ONLY `isOver18 = true`
> and redacts the other four. The library accepts based on the
> registrar's signature over the Merkle root + a proof that the
> disclosed field is committed under that root.

## What this proves

- `createBodyCommitment(body)` produces a stable Merkle root that
  serves as `header.cid` on the signed envelope.
- `createSelectiveDisclosure({ event, body, salts, hiddenFields })`
  produces a transmittable disclosure that reveals only the requested
  fields; the rest appear as opaque leaf-hash inclusion proofs.
- `verifySelectiveDisclosure(disclosure, pubkey)` accepts a
  well-formed disclosure when the disclosed values commit to the
  signed root.
- Tampering with a disclosed value breaks the recomputed root → reject.

## GAP-ZKP-001 — CLOSED in this use case

Surfaced + fixed in the same pass. The previous limitation —
`verifySelectiveDisclosure` not actually checking issuer identity when
fields were redacted — is closed via a new **header attestation**
primitive shipped alongside the use case:

- `signHeaderAttestation(header, signFn)` — issuer-side helper that
  signs `JCS({ header, body: {} })` under DST
  `kash-header-attestation-v1\n`. The body slot is constant-empty so
  the signature stays verifiable across every disclosure the holder
  produces.
- `SelectiveDisclosure.headerAttestation` — optional field on the wire
  shape. Carried through `createSelectiveDisclosure` and verified by
  `verifySelectiveDisclosure` when present.

The `Registrar.issue` method now mints this attestation alongside the
body signature; `StudentWallet.discloseAgeOnly()` passes it through;
the `GAP-ZKP-001 (CLOSED)` test confirms a verifier with the wrong
public key now rejects the disclosure.

See `packages/identity-zkp/src/disclosure.ts` for the upstream
implementation.

## Test result

```
9 pass · 0 fail · 37 expect() calls
```

## Files

- `fixture/age-proof.ts` — `Registrar`, `StudentWallet`, `AdultLibrary` actors
- `fixture/integration.test.ts` — 9 tests across 3 layers
