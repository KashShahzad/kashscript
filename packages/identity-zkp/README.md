# @kashscript/identity-zkp

> **Zero-knowledge primitives for `did:kash`.** Selective disclosure via Merkle commitments + a Web-Worker-dispatched prover/verifier for Groth16 / PLONK circuits.

> **Apache-2.0 from 0.2.4**, the whole package, SNARK prover included (ECOSYSTEM d87). Versions 0.2.1–0.2.3 were published under SSLA Schedule B and keep those terms. See [LICENSE](./LICENSE).

```bash
bun add @kashscript/identity-zkp @kashscript/identity-core
# optional: snarkjs as a peer dep for the prover
bun add snarkjs
```

---

## Two layers, one licence

| Layer                           | Licence       | Purpose                                              |
|---------------------------------|---------------|------------------------------------------------------|
| **Selective disclosure (Merkle)** | Apache-2.0  | Reveal *chosen fields* of a signed Kash-Event body, proving the rest stay committed |
| **SNARK prover (Groth16 / PLONK)** | Apache-2.0 | Generate succinct proofs of arbitrary predicates over identity data |

Most apps need only the Merkle layer; the SNARK prover is for compliance
attestations, age-gating, KYC-once-prove-many flows, and similar
high-assurance use cases.

---

## Quickstart — selective disclosure

```typescript
import { Signer } from "@kashscript/identity-core/signer";
import { encodeBase58 } from "@kashscript/identity-core/base58";
import {
  createBodyCommitment, createSelectiveDisclosure, verifySelectiveDisclosure,
  signHeaderAttestation, KASH_HEADER_ATTESTATION_DST,
} from "@kashscript/identity-zkp/disclosure";

// Issuer: commit the body to a Merkle root, sign it, mint a header attestation.
const issuer = await Signer.generate();
const body = { legalName: "Ayesha Khan", dateOfBirth: "2005-04-15", isOver18: true };
const commitment = await createBodyCommitment(body);          // keep commitment.salts private
const header = { did: issuer.did, cid: encodeBase58(commitment.root) };
const event = { header, body, signature: await issuer.sign(header, body) };
const headerAttestation = await signHeaderAttestation(header, (h) =>
  issuer.sign(h, {}, { dst: KASH_HEADER_ATTESTATION_DST }));

// Holder: reveal only `isOver18`, redact the rest.
const disclosure = await createSelectiveDisclosure({
  event, body, salts: commitment.salts,
  hiddenFields: ["legalName", "dateOfBirth"], headerAttestation,
});

// Verifier: checks the Merkle root + issuer signature; learns nothing hidden.
const ok = await verifySelectiveDisclosure(disclosure, issuer.publicKey);
console.log(ok && disclosure.disclosed.isOver18?.value === true); // true
```

The verifier learns only the disclosed fields + an inclusion proof binding the
redacted ones to the issuer-signed Merkle root — nothing about any hidden field.
Always pass a `headerAttestation`, or redacted-field verification falls back to
honour-system (it stops enforcing issuer identity).

---

## Quickstart — SNARK proving

```typescript
import { setProverWorker, createPrivacyProof } from "@kashscript/identity-zkp/prover";
import { buildRangeProofSpec, toRangeWitness } from "@kashscript/identity-zkp/circuits";
import { Worker } from "node:worker_threads";

// In Node/SSR you MUST inject a Worker (the browser uses one automatically).
setProverWorker(() => new Worker(new URL("@kashscript/identity-zkp/worker", import.meta.url)));

// Circuit artifacts are NOT bundled — supply your own wasm / zkey / verificationKey.
const circuit = buildRangeProofSpec({ wasm, zkey, verificationKey });

// The default range circuit is self-attested — the flag must be set deliberately.
const witness = toRangeWitness({
  value: 25n, salt, threshold: 18n, commitment, // commitment = Poseidon(value, salt)
  _acknowledgesSelfAttested: true,
});

const { proof, publicSignals, elapsedMs } = await createPrivacyProof({ circuit, witness });
```

The worker dispatch is mandatory: SNARK proving is CPU-expensive and must not
block the main thread. The worker uses `snarkjs` under the hood (optional peer
dep — calls throw `SNARKJS_UNAVAILABLE` if it isn't installed).

---

## What's in the box

| Subpath                                | Purpose                                            |
|----------------------------------------|----------------------------------------------------|
| `@kashscript/identity-zkp`             | Default — re-exports merkle, disclosure, prover, verifier, circuits, errors |
| `@kashscript/identity-zkp/merkle`      | SHA-256 Merkle tree primitives (v2, length-prefixed) |
| `@kashscript/identity-zkp/disclosure`  | `createBodyCommitment` / `createSelectiveDisclosure` / `verifySelectiveDisclosure` |
| `@kashscript/identity-zkp/prover`      | SNARK prover client + worker lifecycle |
| `@kashscript/identity-zkp/verifier`    | `verifyPrivacyProof` — main-thread verify |
| `@kashscript/identity-zkp/worker`      | Web-Worker entry point for the prover              |
| `@kashscript/identity-zkp/circuits`    | Circuit specs + witness builders (range, membership). **Artifacts NOT bundled** — supply your own wasm/zkey |
| `@kashscript/identity-zkp/errors`      | `KashZkpError` + typed `KashZkpErrorCode`          |

---

## Licensing

Apache-2.0; see [LICENSE](./LICENSE). Versions 0.2.1, 0.2.2 and 0.2.3 were
published under SSLA Schedule B and keep those terms; every later version
carries Apache-2.0 (`docs/legal/license-matrix.md`, ECOSYSTEM d87). Checking a
record or a proof must not need us (d28), so nothing here asks for a Plan or a
licence token.
