# I/O contract — Cross-device sign-in

## `Device` — one machine's worth of state + ops

Constructor:
```ts
new Device(host: MufflerHost, cfg: { label: string })
```

### `device.provision(handle?: string) → Promise<void>`

| | |
|---|---|
| Effect | Mints a fresh Signer, persists the public envelope + private JWK to storage, wires the publishing consumer. |
| Throws | If already provisioned. |
| Side effects | `storage.write(...)` — local persistence. |
| Idempotency | NOT idempotent — second call throws. Call `signOut()` first. |

### `device.hydrate() → Promise<void>`

| | |
|---|---|
| Effect | Reads the JWK out of storage, rebuilds the Signer, wires the publishing consumer. Should produce the same DID as the original provisioning device. |
| Throws | `Error("no identity in storage to hydrate")` if storage is empty. |
| Side effects | None (read-only). |
| Idempotency | Yes — multiple calls are equivalent. |

### `device.adopt(bundle) → Promise<void>`

| | |
|---|---|
| Input | `{ envelope: StoredKashIdentity, keyJwk: ExportedKey }` from another device's `exportBundle()`. |
| Effect | `storage.importBundle(bundle)` then `hydrate()`. After adoption, this device has the same DID as the source. |
| Side effects | Local storage replaced. |
| Idempotency | Replaces existing state; second adoption with different bundle = device switches identity. |

### `device.publishPost(body: KashSocialPostBody) → Promise<MufflerIngestResult>`

| | |
|---|---|
| Effect | Sign + post a record to the wired Muffler host. |
| Throws | If not provisioned. |
| Returns | `MufflerIngestResult` discriminated union (see ../../muffler-ingest/io.md). |

### `device.exportBundle() → { envelope, keyJwk } \| null` (via `device.storage`)

| | |
|---|---|
| Effect | Read-only export of the full local state. |
| Returns | `null` if device not provisioned; otherwise the portable bundle. |

### `device.signOut() → void`

| | |
|---|---|
| Effect | Wipes both the in-memory Signer and the storage state. Other devices are unaffected. |
| Idempotency | Yes — calling twice is fine. |

### `device.did → string` / `device.publicKey → Uint8Array` / `device.isProvisioned → boolean`

Read-only accessors. `did` and `publicKey` throw if called before provision/adopt.

---

## `HeadlessIdentityStorage` — the GAP-004 workaround adapter

### `storage.write(identity, jwk, handle?)`

| | |
|---|---|
| Input | `KashIdentity` (the public envelope), `ExportedKey` (the JWK), optional handle. |
| Effect | Replaces any prior state. Stores both layers atomically (one in-memory object). |

### `storage.readEnvelope() → KashIdentity \| null`

| | |
|---|---|
| Returns | `null` if nothing stored. Otherwise reconstructs the envelope with `publicKey` and `credentialId` decoded back to bytes. |
| Side effects | None (read-only). |

### `storage.readKeyJwk() → ExportedKey \| null`

| | |
|---|---|
| Returns | The JWK as stored. `null` if no identity. |

### `storage.hasIdentity() → boolean`

Convenience check; equivalent to `readEnvelope() !== null`.

### `storage.clear() → void`

Wipes both layers. Idempotent.

### `storage.exportBundle() → { envelope, keyJwk } \| null`

| | |
|---|---|
| Returns | The complete portable state, or `null`. |
| Used by | The "device transfer" UX. In a real app this is what gets sent through iCloud Keychain / WebAuthn cross-device. |

### `storage.importBundle(bundle) → void`

| | |
|---|---|
| Input | The bundle from `exportBundle()` on another device. |
| Effect | Replaces local state with the imported bundle. |

---

## Layered I/O — what each layer of the test asserts

### Layer 1 (Signer round-trip)

```
Input:   no input (Signer.generate())
Output:  Signer instance
                │
                ├─ exportJwk() → ExportedKey JWK
                │     │
                │     ▼
                ▼   Signer.fromJwk(jwk)
            (same DID, same pubkey bytes)
```

Assertion: rebuilt Signer's `did === original.did` AND `publicKey` bytes are byte-equal.

### Layer 2 (Storage round-trip)

```
Input:   KashIdentity + ExportedKey JWK
        ▼
HeadlessIdentityStorage.write(...)
        ▼
.exportBundle() → JSON-serializable bundle
        ▼
(transfer)
        ▼
HeadlessIdentityStorage.importBundle(bundle)
        ▼
.readEnvelope() → KashIdentity (bytes-equal to input)
.readKeyJwk()   → ExportedKey (deep-equal to input)
```

### Layer 3 (End-to-end Muffler)

```
Input:   nothing
        ▼
Device A.provision() → publishPost(...) → Muffler accepts (1 record)
        ▼
Device A.storage.exportBundle() → bundle
        ▼
Device B.adopt(bundle) → publishPost(...) → Muffler accepts (2nd record, same DID)
        ▼
host.listByCollection(DID, lexicon).length === 2
```

---

## Signer API used (from `@kashscript/identity-core`)

| Method | I/O |
|---|---|
| `Signer.generate()` | First-time provisioning. Returns a Signer with a fresh keypair. |
| `signer.exportJwk()` | Serialise the keypair as a JWK. **Contains the private key bytes** in `d` field. |
| `Signer.fromJwk(jwk)` | Re-hydrate a Signer from a previously-exported JWK. Same DID, same pubkey bytes as the original. |
| `signer.did` / `signer.publicKey` | Derived from the public key half of the keypair. Stable across provisioning + hydrate. |

The Signer's API is **completely deterministic given the same private key bytes**. Two devices with the same JWK produce equivalent Signers, period.

---

## Identity SDK types used

| Type | Source | Used for |
|---|---|---|
| `KashIdentity` | `@kashscript/identity-sdk` | The runtime shape — DID + pubkey + credentialId, optional handle. |
| `StoredKashIdentity` | `@kashscript/identity-sdk` | The persisted shape — base58 / base64url encodings + ISO-8601 timestamp. |
| `ExportedKey` | `@kashscript/identity-core/keys` | The JWK form. `kty: "OKP"` / `crv: "Ed25519"` + `x` (pubkey) + `d` (private seed). |
