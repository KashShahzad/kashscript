# Kash ZKP — Privacy Spec
**`specs/zkp-implementation.md` — Phase 5 · Developer Guide for `@kashscript/identity-zkp`**

> **Update note (2026-05-28):** GAP-ZKP-001 closed via new
> `signHeaderAttestation` primitive + optional
> `SelectiveDisclosure.headerAttestation` field. F4 anti-linkability
> primitives `reSaltCommitment` + `findLinkableLeaves` shipped. SNARK
> prover end-to-end flagship still deferred (needs ptau ceremony).
> Shipped as identity-zkp@0.2.2. Full delta in
> `specs/audit-2026-05-28-updates.md` (an internal change log, not in the public repository) §5.

> Privacy primitives for the `did:kash` ecosystem. Two layers, used independently:
>
> 1. **Selective Disclosure** (no SNARK needed) — sign a Kash-Event once, reveal any subset of its fields later without invalidating the signature. Pure SHA-256 + Merkle trees.
> 2. **Predicate Proofs** (Groth16 / PLONK via `snarkjs`) — prove a property about a hidden value (e.g., age ≥ 18, balance ≥ N, registry membership) without revealing the value. Runs inside a Web Worker so the main thread stays responsive.
>
> This document is the developer-facing guide. The cryptographic rationale and protocol-level rules live in [identity-protocol-v1.md §6.2](./identity-protocol-v1.md).

---

## 0. When to use which

| Goal                                                              | Use                          |
|-------------------------------------------------------------------|------------------------------|
| "Show only my display name from my signed profile."               | Selective Disclosure         |
| "Prove I have a Duedale receipt over $100 without revealing it."  | Range Proof                  |
| "Prove I'm on the verified-seller registry without saying which seller." | Membership Proof       |
| "Prove I'm over 18."                                              | Range Proof (age ≥ 18)       |
| "Prove I hold ≥ 50 PKR worth of tokens."                          | Range Proof (balance ≥ 50)   |

Selective Disclosure is the cheaper, simpler tool. Reach for SNARKs only when you need to prove a **predicate** about a hidden value.

---

## 1. Selective Disclosure — quickstart

### 1.1 Commit at signing time

Before signing a Kash-Event, replace the conventional `header.cid = SHA-256(canonicalize(body))` with a Merkle commitment:

```typescript
import { createBodyCommitment } from "@kashscript/identity-zkp";
import { encodeBase58 }         from "@kashscript/identity-core";

const body = {
  displayName: "Kashif Shahzad",
  bio:         "Building the SSL.",
  birthDate:   "1992-06-15",   // ← we want to keep this private later
  country:     "PK",
};

const { root, fieldOrder, salts } = await createBodyCommitment(body);

// Use the root as the cid; persist `salts` privately (e.g., IndexedDB).
const header = {
  did:     "did:kash:5g7q…",
  lexicon: "kash.id.profile@1.0.0",
  iat:     "2026-05-11T12:00:00Z",
  nonce:   "…",
  cid:     `z${encodeBase58(root)}`,   // multibase-tagged Merkle root
  rkey:    "self",
};

// Sign as usual with identity-core's signEvent / Signer.
```

The `salts` map is the user's private "disclosure capability" — anyone who holds it can later prove `body[k] = v` for any field `k` without unveiling the others.

### 1.2 Disclose only what's needed

```typescript
import { createSelectiveDisclosure } from "@kashscript/identity-zkp";

const disclosure = await createSelectiveDisclosure({
  event:         signedEvent,            // the envelope with the Merkle root
  body,                                  // the original full body
  salts,                                 // private salts from step 1.1
  hiddenFields:  ["birthDate", "bio"],   // redact these
});

// Transmit `disclosure` instead of the full event.
```

`disclosure` contains:
- The verbatim `header` and `signature`.
- `disclosed[k] = { value, saltB58 }` for revealed fields.
- `redacted[k] = { leafB58, siblingsB58[], positions[] }` for hidden fields — the leaf hash plus its Merkle inclusion path.
- `fieldOrder[]` — alphabetically-sorted field names, fixing the leaf order.

### 1.3 Verify

```typescript
import { verifySelectiveDisclosure } from "@kashscript/identity-zkp";
import { parseDid }                  from "@kashscript/identity-core";

const publicKey = parseDid(disclosure.header.did as string);
const ok        = await verifySelectiveDisclosure(disclosure, publicKey);
```

Returns `true` iff:
1. Every disclosed field hashes (with its supplied salt) to a leaf that participates in the recovered root.
2. Every redacted leaf participates in the recovered root.
3. The recovered root equals `header.cid`.
4. The signature still validates over the (header, root) commitment.

A malicious holder cannot lie about hidden fields — the leaf hash is opaque but its membership in the signed root is proven mathematically.

---

## 2. Predicate Proofs — Quickstart

The SNARK side requires three things from the consumer:

1. A **circuit** (compiled `.wasm` for witness generation + `.zkey` for proving).
2. A **trusted-setup ceremony output** (the verification key derived from the `.zkey`).
3. **`snarkjs`** installed as a peer dependency (`bun add snarkjs`).

This package ships the orchestration; circuits + ceremonies are a separate deliverable (`specs/zkp-circuits/`).

### 2.1 Proof of Age

Reusable concept: prove `myAge >= threshold` without revealing `myAge`.

**Circuit interface** (consumer-supplied wasm/zkey/vk):

```typescript
import {
  buildRangeProofSpec,
  PROOF_OF_AGE_CIRCUIT_ID,
  rangeProof,                  // namespace: rangeProof.toWitness, .RangeProofWitness, …
  createPrivacyProof,
} from "@kashscript/identity-zkp";

const circuit = buildRangeProofSpec({
  id:     PROOF_OF_AGE_CIRCUIT_ID,
  system: "groth16",
  wasm:   "/circuits/proof-of-age.wasm",
  zkey:   "/circuits/proof-of-age.zkey",
  verificationKey: verificationKey,           // loaded from your CDN
  description:    "Prove age >= threshold",
});
```

**Holder side** — generate the proof:

```typescript
const myAge      = 33n;
const salt       = 1234567890n;                          // 254-bit random
const threshold  = 18n;
const commitment = await poseidonCommit(myAge, salt);    // user-side helper

const { proof, publicSignals, elapsedMs } = await createPrivacyProof({
  circuit,
  witness: rangeProof.toWitness({
    value:      myAge,
    salt,
    threshold,
    commitment,
  }),
});

console.log(`Proof generated in ${elapsedMs}ms`);
// Send { proof, publicSignals, commitment, threshold } to the verifier.
```

The witness construction runs inside a **Web Worker** by default — the main thread is free to keep rendering while Groth16 grinds for the few seconds it needs.

**Verifier side** — Indusland, Duedale, or any third party:

```typescript
import { verifyPrivacyProof } from "@kashscript/identity-zkp";

const ok = await verifyPrivacyProof({
  proof,
  publicSignals,                  // [commitment, threshold]
  verificationKey,
});

if (ok) {
  // The holder really is at least 18.
  // We saw zero bytes of their actual age.
}
```

Verification runs on the main thread (single-digit milliseconds for Groth16).

### 2.2 Proof of Balance

Same circuit family as Proof of Age — just a different witness:

```typescript
const myBalance  = 50_000n;                      // amount in minor units (paisa)
const salt       = …;
const threshold  = 100_00n;                      // claim: I hold ≥ 100 PKR
const commitment = await poseidonCommit(myBalance, salt);

const { proof, publicSignals } = await createPrivacyProof({
  circuit:  proofOfBalanceCircuit,               // built the same way as above
  witness:  rangeProof.toWitness({ value: myBalance, salt, threshold, commitment }),
});
```

### 2.3 Proof of Registry Membership

For "I'm a verified seller" / "I'm on the allowlist" without revealing which member:

```typescript
import {
  buildMembershipProofSpec,
  PROOF_OF_REGISTRY_MEMBERSHIP_CIRCUIT_ID,
  membershipProof,
} from "@kashscript/identity-zkp";

const circuit = buildMembershipProofSpec({
  id:     PROOF_OF_REGISTRY_MEMBERSHIP_CIRCUIT_ID,
  wasm:   "/circuits/membership.wasm",
  zkey:   "/circuits/membership.zkey",
  verificationKey,
});

const { proof, publicSignals } = await createPrivacyProof({
  circuit,
  witness: membershipProof.toWitness({
    didFE:        didToFieldElement(myDid),
    siblings:     [/* 20 sibling hashes, leaf-to-root */],
    pathBits:     [/* 20 zero/one bits matching siblings */],
    registryRoot: knownRegistryRoot,                  // public
    namespaceTag: hashOfRegistryId,                   // public, prevents cross-registry replay
  }),
});
```

---

## 3. The Web Worker contract

`createPrivacyProof` dispatches to a Web Worker module bundled with this package at `@kashscript/identity-zkp/worker`. Modern bundlers (Bun, Vite, Webpack 5, esbuild) construct it via `new URL("./worker.ts", import.meta.url)` automatically.

If your bundler refuses or you're sharing a worker across modules, inject your own:

```typescript
import { setProverWorker } from "@kashscript/identity-zkp";

setProverWorker(() => new Worker(
  new URL("./my-shared-zkp-worker.ts", import.meta.url),
  { type: "module" },
));
```

Your custom worker must speak the same message envelope (see [worker.ts](../packages/identity-zkp/src/worker.ts)) — `kind: "prove" | "verify"`, response `{ id, ok, result | error }`.

### 3.1 Why a Worker

A Groth16 fullProve for a small circuit (10–20k constraints) takes 0.5–5 seconds on a modern laptop and even longer on a mid-range phone. Running it on the main thread freezes the UI for the duration — unacceptable for a Trust-UX product. The Worker keeps the main thread interactive: animations keep playing, inputs keep responding, and the user sees a real progress signal.

### 3.2 Tear-down

```typescript
import { teardownProver } from "@kashscript/identity-zkp";

teardownProver();   // terminate the worker, reject pending promises
```

Useful in tests, hot-reloading dev environments, and SPA route changes that no longer need the prover.

---

## 4. Circuit-artefact contract

For each circuit you ship, your CDN / package needs three files:

| Artefact            | Producer                          | Purpose                                  |
|---------------------|-----------------------------------|------------------------------------------|
| `<circuit>.wasm`    | `circom --wasm`                   | Witness generation in the prover.        |
| `<circuit>.zkey`    | `snarkjs setup` + `contribute`    | Proving key. Trusted-setup output.       |
| `<circuit>.vkey.json` | `snarkjs zkey export verificationkey` | Public verification key — embeddable in apps. |

The `verificationKey` is JSON and small (~3 KB for Groth16). Bundle it in your verifier app or fetch from a known URL. The `.wasm` and `.zkey` are larger (hundreds of KB to a few MB) and should be served with long-lived caching.

> Build-pipeline reference (out of scope for this package): see `specs/zkp-circuits/README.md` for the recommended Powers-of-Tau ceremony, circom compilation flow, and CI pinning of artefact hashes.

---

## 5. Wire format

### 5.1 SelectiveDisclosure (JSON-LD friendly)

```jsonc
{
  "header": { "did": "did:kash:…", "lexicon": "kash.id.profile@1.0.0", "cid": "zBg…", "…": "…" },
  "signature": { "alg": "ed25519", "sig": "…", "dst": "kash-record-v1\n", "encoding": "base64url", "kid": "did:kash:…#sig-1" },
  "disclosed": {
    "displayName": { "value": "Kashif Shahzad", "saltB58": "3jK8x…" },
    "country":     { "value": "PK",              "saltB58": "9qP2z…" }
  },
  "redacted": {
    "birthDate": {
      "leafB58":    "Lh7…",
      "siblingsB58":["A1…","B2…","C3…"],
      "positions":  [0, 1, 0]
    },
    "bio": { "leafB58": "Mr9…", "siblingsB58": ["…"], "positions": [1] }
  },
  "fieldOrder": ["bio", "birthDate", "country", "displayName"]
}
```

### 5.2 Predicate Proof envelope

Pass the snarkjs-shaped `proof` + `publicSignals` arrays directly. The verifier checks `proof.protocol === verificationKey.protocol`; mismatches throw `INVALID_VERIFICATION_KEY`.

---

## 6. Error model

| Code                          | When                                                                        |
|-------------------------------|-----------------------------------------------------------------------------|
| `INVALID_BODY`                | `createBodyCommitment` got a non-object or empty body.                       |
| `DISCLOSURE_SALT_MISMATCH`    | Salts map doesn't mirror body keys.                                          |
| `DISCLOSURE_LEAF_MISMATCH`    | A disclosed value+salt doesn't hash to its committed leaf.                   |
| `DISCLOSURE_PATH_MISMATCH`    | A redacted leaf's inclusion proof doesn't reconstruct the root.              |
| `DISCLOSURE_ROOT_MISMATCH`    | Body+salts produce a root that differs from `header.cid`.                    |
| `DISCLOSURE_INVALID_ROOT`     | `header.cid` is absent or not a 32-byte base58btc root.                      |
| `SNARKJS_UNAVAILABLE`         | The optional `snarkjs` peer dep isn't installed.                             |
| `WORKER_UNAVAILABLE`          | No Web Worker support and no custom factory supplied.                        |
| `WORKER_FAILED`               | Worker reported a runtime error during prove / verify.                       |
| `INVALID_CIRCUIT_SPEC`        | Circuit spec is missing wasm/zkey/verificationKey.                           |
| `INVALID_WITNESS`             | Witness shape doesn't match the circuit's declared inputs.                   |
| `INVALID_VERIFICATION_KEY`    | VK is malformed or proof-system mismatch with the proof.                     |
| `INVALID_PROOF`               | Proof bytes are malformed for the declared proof system.                     |

---

## 7. Threat model

### 7.1 In-scope and addressed

- **Field-level hiding** — Merkle leaves with per-field salts prevent value-guessing on low-entropy fields. Salts are 32 bytes (256 bits) — brute-force-infeasible.
- **Tampered disclosure** — every disclosed value + salt is hashed and compared to the participating leaf. Verifier never trusts the holder's claim about a field without recomputing.
- **Leaf-encoding ambiguity (F5)** — leaves are length-prefixed (`u32be(len)`) with a `kash-leaf-v2\n` DST; internal nodes use `kash-merkle-internal-v2\n`. No (data, salt) pair can collide with a longer-data / shorter-salt cousin under concatenation.
- **Replay of proofs across registries** — `namespaceTag` in the membership circuit binds the proof to a specific registry id.
- **Cross-verifier replay (F4)** — `rebindForVerifier` wraps a disclosure with `audience` + `nonce` + `expiresAt` + `bindingHash`. Verifiers MUST unwrap with their own expected audience; replay across audiences is rejected by the hash check.
- **Wire-level schema-shape leak (F4)** — `fieldOrder` removed from the disclosure envelope. Verifiers derive canonical order from `Object.keys(disclosed ∪ redacted).sort()`. An all-redacted disclosure now leaks only the field NAMES the holder chose to redact (it always leaked those — the field names are the verifier's request shape) and the number of disclosed fields, not the schema's broader shape.
- **Main-thread freezing** — Worker-dispatched proof generation.
- **Aborted UX (F2)** — `AbortSignal` on `createPrivacyProof()` returns control to the caller immediately; the worker swallows the eventual snarkjs completion. `configureProver({ idleTimeoutMs })` reclaims the ~10 MB snarkjs heap when the user backs out of a flow.
- **Trusted-setup compromise** — out of scope at the package level; each circuit ships its own ceremony provenance.

### 7.2 Out of scope (acknowledged)

- **Side-channel attacks** (timing, memory) on the holder's device.
- **Holder pre-image leakage** — if the holder publishes the salt for a leaf elsewhere, the protection on that leaf is broken. Treat salts as secrets equivalent to private keys.
- **Leaf-hash linkability across disclosures (F4)** — for a given (key, value, salt), the leaf hash is deterministic. Reusing a single signed commitment across two verifiers means the same redacted leaf hash appears in both. Two verifiers colluding can correlate the user. **Mitigation:** holders MUST re-sign per verifier when unlinkability matters; the SNARK route is the right tool for attribute-equality-without-correlation.
- **Quantum cryptanalysis** — Groth16 over BN254 is not post-quantum; track Identity-Bible §13.6 for migration plans.

### 7.3 SNARK-specific advisories (F1, F3)

- **Self-attestable range proofs (F1, CRITICAL).** The bare circuit (`kash-range-proof-on-commitment-v1`) proves: `commitment == Poseidon(value, salt)` AND `value >= threshold`. It does NOT verify any issuer attestation on `value`. A prover can pick any `value`, mint a fresh `commitment`, and produce a sound proof. **The bare circuit is NOT a Proof of Age / KYC / salary / anything attribute-level.** The forthcoming `kash-attested-range-proof-v1` extends the witness with `attestationSig`, `issuerPubkey`, and `payloadCommit`, verifying an Ed25519-in-circuit issuer signature over `payloadCommit`. Until those artefacts ship, callers wanting real attribute claims MUST compose this circuit with out-of-band attestation checks or wait for v0.4. The TypeScript layer enforces caller-acknowledgement: `toRangeWitness` refuses to build a witness without an explicit `_acknowledgesSelfAttested: true` marker.
- **Transport-layer linkability (F3).** A SNARK proof, by itself, is unlinkable across submissions IF the submission envelope does not carry persistent-DID identifiers. The `kash.zkp.proof-of-claim@1.0.0` lexicon (extensions/zkp) requires a `submitWith` discriminator with three modes:
  - `"ephemeral-keypair"` — a fresh one-shot keypair signs the envelope. The verifier sees no persistent identity. UNLINKABLE (across verifiers; across submissions to the same verifier; across time).
  - `"session-keypair"` — a per-verifier session key signs. LINKABLE within session; unlinkable across verifiers/sessions.
  - `"persistent-keypair"` — the holder's long-lived DID signs. FULLY LINKABLE.

  Verifiers MUST surface the chosen mode in their UX (e.g., "this proof was submitted anonymously" vs "submitted by did:kash:abc…"). The default for privacy-sensitive flows is `"ephemeral-keypair"`; callers opt INTO linkability by choosing one of the others.

---

## 8. Performance ballpark

Measured on a 2024 MacBook Air M3, Chrome 138, Bun 1.2.5:

| Operation                                              | Time      |
|--------------------------------------------------------|-----------|
| `createBodyCommitment` (8 fields)                      | < 1 ms    |
| `createSelectiveDisclosure` (8 fields, 4 redacted)     | < 2 ms    |
| `verifySelectiveDisclosure` (8 fields, 4 redacted)     | < 3 ms    |
| Groth16 `fullProve` (~10k constraints, range proof)    | 600–900 ms (Worker) |
| Groth16 `fullProve` (~50k constraints, membership)     | 1.8–3.5 s (Worker)  |
| Groth16 `verify`                                       | 4–8 ms    |

Numbers grow with circuit size and shrink with newer browser JIT improvements. The Worker-dispatched path is what makes the multi-second prove acceptable — the main thread is never blocked.

---

## Change Log

| Version | Date       | Summary                                                                  |
|---------|------------|--------------------------------------------------------------------------|
| **v0.1** | 2026-05-11 | Initial release — selective disclosure (Merkle + SHA-256), prover/verifier orchestrator, Web Worker dispatcher, circuit specs for range and membership proofs. |
| **v0.2** | 2026-05-11 | **Audit-R1 hardening (F1–F5).** **Selective disclosure:** length-prefixed leaf encoding (`u32be(len) \|\| data` segments, F5), `kash-leaf-v2\n` / `kash-merkle-internal-v2\n` DSTs, `fieldOrder` removed from the wire (F4 — verifier derives it from `Object.keys(disclosed ∪ redacted).sort()`), new `rebindForVerifier()` / `unwrapVerifierBoundDisclosure()` helpers (F4) for audience-bound envelopes. **SNARK layer:** circuit id renamed `kash-proof-of-age-v1` → `kash-range-proof-on-commitment-v1` (F1) to truthfully signal limited semantics; `RangeProofWitness` now requires `_acknowledgesSelfAttested: true`; `AttestedRangeProofWitness` reserved for v0.4 with `attestationSig` / `issuerPubkey` / `payloadCommit`. **Prover UX (F2):** `signal: AbortSignal`, `onProgress`, `estimateProofCost(circuit)`, `configureProver({ idleTimeoutMs })`. **New lexicon (F3):** `kash.zkp.proof-of-claim@1.0.0` in `@kashscript/lexicons/extensions/zkp` carrying a `submitWith` discriminator (ephemeral / session / persistent keypair) so verifiers can reason about linkability at the transport. §7 Threat Model split into 7.1 (in-scope), 7.2 (out-of-scope including leaf-hash linkability), 7.3 (SNARK-specific advisories). |
| **v0.3** | 2026-07-04 | **Terminology unification (ROADMAP P0).** DID method label unified to `did:kash`, matching the shipped `@kashscript/identity-core` runtime (which enforces `did:kash` and rejects the retired spelling). Prose/label change only; no protocol-semantic change. |
