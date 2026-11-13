# Policies — Cross-device sign-in

The cross-device flow is governed by what "same identity" means cryptographically, and how a bundle should be transferred between devices. Most of the policies are statements of invariant rather than configurable knobs — they're the rules the protocol assumes hold.

---

## P-001 · Same JWK ⇒ Same DID ⇒ Same Authority

**Rule:** if two `Signer` instances are constructed from byte-identical JWKs, they have identical DIDs and identical signing authority.

**Why:** the DID is `did:kash:<base58btc(pubkey)>`. The pubkey is half of an Ed25519 keypair. Two keypairs with byte-identical private seeds produce byte-identical public keys → byte-identical DIDs. Any signature produced by either Signer is a signature from "Alice" — the verifier cannot distinguish them, and doesn't need to.

**Configurable:** no — this is the cryptographic invariant the use case depends on.

**Implication for product UX:** "the same account" on two devices means "the same private key on two devices." There's no per-device sub-identity; revoking one device requires rotating the keypair (a recovery operation, separate use case).

---

## P-002 · Bundle transfer is out-of-band

**Rule:** the act of moving a bundle from Device A to Device B is NOT part of the SDK's surface. KashScript provides `exportBundle()` and `importBundle()` — the transfer is the user's responsibility.

**Why:** the right transfer mechanism depends on the platform:
- Apple ecosystem → iCloud Keychain key sync (E2EE managed by Apple)
- Google ecosystem → Google Password Manager
- Cross-vendor → WebAuthn cross-device authentication (FIDO Alliance protocol; QR code scanning)
- Self-managed → encrypted file backup; manual import on the new device

Trying to bake all four into the SDK would be a worse outcome than letting the OS handle it.

**Configurable:** N/A. The bundle format is stable; the transport is open.

**Risk:** if the transfer is compromised, the identity is compromised. The bundle contains the private key seed.

---

## P-003 · The credentialId field is WebAuthn-specific

**Rule:** `StoredKashIdentity.credentialIdB64u` is a WebAuthn artefact — it's the opaque handle the browser hands back from `navigator.credentials.create()`.

**Why:** in a real browser app, the credentialId tells WebAuthn which Passkey to use on the next assertion. It's part of the storage envelope so the SDK can present it to WebAuthn calls.

**For headless consumers:** the field is required by the storage schema, but its content is meaningless. The fixture's `HeadlessIdentityStorage` synthesises one from the pubkey to satisfy the shape. A future headless adapter could leave it empty or relax the requirement.

**Status:** the requirement should be relaxed in `identity-sdk` v2 — the field belongs in a `BrowserKashIdentity` subtype, not the base `KashIdentity`.

---

## P-004 · Sign-out is local-only

**Rule:** `device.signOut()` wipes that device's storage. It does NOT revoke the keypair, NOT notify other devices, NOT inform Muffler.

**Why:** sign-out is a UX action ("I want this device to forget I was here"), not an authorization revocation. Other devices that hold the same JWK can still sign as Alice.

**To actually revoke** the keypair (e.g., because a device was lost), the user must run the **social-recovery flow** (use case #3): a guardian quorum signs a new DID Document that rotates the active key. Old signatures remain valid (they were valid at signing time), but new ones from the lost device's key won't be accepted by any host that's seen the rotation.

**Configurable:** no — these semantics are deliberate. Conflating "log out" with "burn the key" would surprise users.

---

## P-005 · Multiple-device publishes don't collide if rkeys differ

**Rule:** Devices A and B can both publish to the same `(did, lexicon)` collection on Muffler. The host applies `RKEY_DUPLICATE` (use case 1 / P-002 in muffler-ingest) per `(did, lexicon, rkey)`.

**Why:** the auto-generated rkey is derived from the body's CID, which is content-addressed. Different posts → different rkeys → no collision. If both devices independently compose the EXACT same post (byte-identical body), the second publisher loses the race.

**Mitigation in product UX:** the Indusland client can offer a "draft conflict" toast if a publish fails with `RKEY_DUPLICATE` — likely the user posted the same thing from two devices.

---

## P-006 · No client-side timing skew tolerance

**Rule:** the `iat` field on the envelope is the device's local clock at sign time. Devices can have skewed clocks; the host accepts whatever they send (see use case 1 / P-008).

**Why:** clock-skew enforcement is brittle. Users travel; phones change time zones; some devices have wildly wrong clocks. Trying to gate publishing on clock-correctness would create false negatives. The nonce + rkey-uniqueness checks already prevent replay; iat is informational.

**Cross-device implication:** if Device A and Device B have skewed clocks, a record from B might `iat` "before" a record from A even if A was actually published first. Order-sensitive consumers should not trust `iat` alone — use `seq` + `prev` for proper ordering.

---

## P-007 · Bundle format is stable across SDK versions

**Rule:** the `{ envelope, keyJwk }` shape produced by `exportBundle()` is part of the wire-format contract. Future SDK versions must accept old bundles for at least one minor cycle.

**Why:** users sync devices intermittently. A bundle exported in v0.2 might be imported on v0.4 — the format must round-trip. The JWK shape is governed by RFC 7517 (stable); the envelope shape is governed by `StoredKashIdentity` (which can grow optional fields but not change required ones).

**Configurable:** no — this is a wire-format commitment.

---

## P-008 · Signer's privateKey never leaves the JWK

**Rule:** the SDK does not provide a method to extract the raw private key bytes from a Signer. Even `exportJwk()` returns the JWK shape, not the raw 32-byte seed.

**Why:** the JWK is the lowest-level export; everything below it is "the implementation will not give you that." This is a hardening posture against accidental key leakage to logs, error messages, or telemetry. The internal `KashKeyPair` is held in a closure inside the Signer class.

**Cross-device implication:** the bundle's `keyJwk` field is the *minimum* surface to do a cross-device transfer. A consumer that wants to do something stricter (e.g., wrap the seed in a passphrase before transfer) must do it on top of the JWK, not inside the SDK.

---

## Default cross-device posture

For a typical Indusland-like client:
1. **Trust the OS for transfer.** Let Apple Keychain / Google Password Manager handle the cross-device JWK sync.
2. **Auto-hydrate on app boot** if storage has an identity.
3. **Offer manual export** as an escape hatch — user-initiated download of `exportBundle()` as JSON, optionally encrypted with a user passphrase.
4. **Sign-out is "this device forgets"** — never use sign-out as a security action. For revocation, route the user to the recovery flow.
