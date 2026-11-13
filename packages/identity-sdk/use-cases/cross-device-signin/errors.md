# Errors — Cross-device sign-in

Two layers of error here. Runtime errors a consumer can hit (mostly preventable), plus the one artifact gap this use case surfaced (with the proposed upstream fix).

---

## Runtime errors

### `"<label>: already provisioned"` (from `Device.provision`)

**When:** `provision()` is called on a device that already has a Signer.

**Why:** double-provisioning would replace the keypair, generating a *new* DID and orphaning all previously-published records.

**What to do:**
- Call `device.signOut()` first if the user wants to "switch identities" on this device.
- Or, more commonly, the app's boot logic should check `storage.hasIdentity()` and call `hydrate()` instead of `provision()`.

---

### `"<label>: no identity in storage to hydrate"` (from `Device.hydrate`)

**When:** `hydrate()` is called but storage is empty.

**Why:** there's nothing to rehydrate. Common cause: user hit sign-out + the app's boot logic blindly calls `hydrate()` instead of checking first.

**What to do:**
- Wrap the hydrate path with a check: `if (storage.hasIdentity()) await device.hydrate() else show "sign in" UI`.

---

### `"<label>: not yet provisioned"` (from accessors / publishPost)

**When:** consumer code tries to read `device.did` / `device.publicKey` or call `device.publishPost(...)` before `provision()` / `hydrate()` / `adopt()` has run.

**Why:** the device has no Signer instance to back the operation.

**What to do:**
- Gate the calls on `device.isProvisioned`.

---

### `STORAGE_CORRUPT` (only from the SHIP-WITH browser storage)

Not raised by `HeadlessIdentityStorage`; mentioned here because the ship-with `@kashscript/identity-sdk/storage` raises it when localStorage contains junk JSON or missing fields.

**Why:** the user could've manually edited localStorage, or a partial write left invalid state.

**What to do:**
- The browser path catches this and re-prompts for sign-in. The headless adapter doesn't have this failure mode because it holds the state in-memory in its own typed shape.

---

## Artifact gaps surfaced

### GAP-004 · `identity-sdk/storage` is browser-only

**Symptom:** any consumer running in Bun, Node, Deno, Cloudflare Workers, or any non-browser runtime cannot import `readStoredIdentity` / `writeStoredIdentity` from `@kashscript/identity-sdk/storage` — the module checks `typeof window === "undefined"` and bails. There's no pluggable adapter pattern, no headless implementation, no extension seam.

**Root cause:** the storage module was authored for the React-app use case only. Every headless consumer (the `kash` CLI binary, server-side code that needs to verify or sign on behalf of a service identity, a Bun script doing batch imports) ends up writing the same in-memory or file-backed adapter from scratch.

**Workaround applied:** the use-case fixture ships `HeadlessIdentityStorage` — an in-memory adapter implementing the same `KashIdentity` + `StoredKashIdentity` shapes. The Device class uses it directly; no SDK changes were needed for the test to run.

**Upstream fix (recommended in order of decreasing priority):**

1. **Define an `IdentityStorageAdapter` interface** in `identity-sdk/storage`:
   ```ts
   interface IdentityStorageAdapter {
     readEnvelope(): Promise<KashIdentity | null>;
     writeEnvelope(identity: KashIdentity, jwk: ExportedKey): Promise<void>;
     clear(): Promise<void>;
     exportBundle(): Promise<{ envelope: StoredKashIdentity; keyJwk: ExportedKey } | null>;
     importBundle(bundle: { envelope: StoredKashIdentity; keyJwk: ExportedKey }): Promise<void>;
   }
   ```
2. **Refactor the existing browser code** to implement that interface as `BrowserIdentityStorage`.
3. **Add a sibling `HeadlessIdentityStorage`** (in-memory) for tests + scripts. Lift directly from the fixture.
4. **Optionally add `FileIdentityStorage`** (for `~/.kash/credentials.json` — currently each CLI consumer reimplements this).
5. Have `KashAuthProvider` accept an optional `storage` prop — defaults to `BrowserIdentityStorage` for backward compatibility; tests can inject a `HeadlessIdentityStorage`.

**Status:** workaround applied; upstream fix is open work. Roughly a half-day refactor in `identity-sdk` once we commit to it.

---

## Catalogue of NOT errors

A few things consumers might EXPECT to fail but that the use case proves work fine:

| Scenario | Expected outcome | Actual outcome | Why |
|---|---|---|---|
| Same Signer's `exportJwk()` called twice | Same JWK both times? | Yes, byte-identical. | The JWK is a pure function of the keypair. |
| Two devices publish concurrently | rkey collision? | No, the auto-derived rkeys differ if bodies differ. | rkey derivation is content-addressed via the body CID. |
| One device signs out; the other publishes | Both lose identity? | No — sign-out is local-only (P-004). | Sovereignty: the key isn't tied to a server. |
| Adopt an already-adopted bundle | Idempotent? | Yes — `importBundle()` replaces; rebuilding the Signer is deterministic. | The Signer-from-JWK path is pure. |

These are the comforting properties. The whole point of the use case is to confirm them at the integration level, not just trust the unit tests.

---

## Test results

```
12 pass
 0 fail
37 expect() calls
```

All Layer-1 (Signer round-trip), Layer-2 (storage round-trip), and Layer-3 (end-to-end Muffler) properties verified.
