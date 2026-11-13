# Errors — Muffler ingest

Every code a consumer can see, mapped to:
- **When** it fires
- **Why** (which check failed)
- **What to do** (remediation)
- **Test reference** (which case in `integration.test.ts` exercises it)

The codes are stable wire format. The diagnostic `message` field is for humans; never parse it.

---

## Ingest error codes

### `ENVELOPE_MALFORMED`

**When:** Stage 1. The wire envelope is missing required fields, has the wrong shape, or a field violates a format pattern (DID, CID, nonce, iat, lexicon-id, multibase, etc.).

**Why:** the lexicon engine refuses to even consider this an envelope. Probably the consumer is using a stale envelope shape, or a non-Kash-Event was POSTed to the host by accident.

**What to do:**
- Check `details.path` — points at the first malformed field.
- Common culprits: nonce too short (<32 hex), iat missing timezone offset, header.cid not `bafy[a-z2-7]{52,}`, header.did not matching `did:kash:[1-9A-HJ-NP-Za-km-z]{32,48}`.

**Test:** `error paths > ENVELOPE_MALFORMED — required header field missing`.

---

### `LEXICON_UNKNOWN`

**When:** Stage 2 or Stage 4. Either the host's `LexiconRegistry` doesn't contain `event.header.lexicon`, or the host policy's `lexiconAllowlist` explicitly excludes it.

**Why:** the host doesn't know how to validate this kind of record.

**What to do:**
- Confirm the host has registered the lexicon (the social extension is opt-in, not auto-loaded).
- If the host runs a policy allowlist, check whether the lexicon is in it.

**Test:**
- `error paths > LEXICON_UNKNOWN — host without the social extension registered`
- `error paths > LEXICON_UNKNOWN — host policy excludes lexicon from allowlist`

---

### `LEXICON_VALIDATION_FAILED`

**When:** Stage 3. The envelope shape is correct AND the lexicon is registered, but `event.body` violates the lexicon's body schema.

**Why:** the consumer composed a body that breaks a domain constraint — text too long, too many media refs, an invalid mime type, a malformed reference.

**What to do:**
- Inspect `details.issues` — points at the field that failed.
- The lexicon's body schema is authoritative (it lives in `@kashscript/lexicons/extensions/social` for `kash.social.post`).

**Test:** `error paths > LEXICON_VALIDATION_FAILED — post body violates the schema (text too long)`.

---

### `DID_DERIVE_FAILED`

**When:** Stage 5. The DID method body (the part after `did:kash:`) can't be base58btc-decoded into a 32-byte pubkey.

**Why:** the DID claimed in the envelope is malformed beyond what the format regex catches. E.g., the regex accepted the length but the actual character sequence doesn't decode.

**What to do:**
- Likely a forged or corrupted envelope. The consumer side shouldn't produce these — identity-core's `deriveDid` is deterministic.
- If you're getting this in production, it's an attack signal.

**Test:** indirectly covered by `error paths > DID_MISMATCH` (the assertion accepts either code).

---

### `DID_MISMATCH`

**When:** Stage 6. The DID's body decodes to a pubkey, but `deriveDid(pubkey)` produces a *different* DID than the one claimed in the header.

**Why:** the consumer is claiming a DID that doesn't actually correspond to the key they signed with. This is the textbook sovereignty-violation attempt.

**What to do:**
- Reject. There's no legitimate reason this fires.
- Surface to the host's abuse-monitoring layer.

**Test:** `error paths > DID_MISMATCH — envelope claims a DID it can't derive from its key`.

---

### `SIGNATURE_INVALID`

**When:** Stage 7. The signature, after bridging to identity-core shape, does not verify against the derived pubkey + the canonical envelope bytes + the declared DST.

**Why:** Either:
1. The body or header was mutated after signing.
2. The DST in the signature doesn't match what was actually used to sign (encoding error in the consumer).
3. The key used to sign isn't the key derived from the DID (covered by `DID_MISMATCH`, but a really determined attacker could still trip this).
4. Cryptographic primitive bug (unlikely; Ed25519 is well-tested).

**What to do:**
- Reject. This is the cryptographic backstop.

**Test:** `error paths > SIGNATURE_INVALID — tampered body after signing`.

---

### `DST_MISMATCH`

**When:** Stage 8. The signature is cryptographically valid, but its DST doesn't match the host's policy `requiredDst`.

**Why:** the consumer signed under a different DST than this host requires. Most often: the host has tightened policy to a custom DST (e.g., `kash-strict-dst-v2\n`), but the consumer didn't get the memo.

**What to do:**
- Consumer side: configure the Signer to use the host's required DST via `SignEventOptions.dst`.
- Host operator side: confirm the policy is what you intended.

**Test:** `error paths > DST_MISMATCH — host policy requires a non-default DST`.

---

### `RKEY_DUPLICATE`

**When:** Stage 9. A record with the same `(did, lexicon, rkey)` is already in storage.

**Why:** the consumer is trying to write to an addressed location that's already taken. The default rkey-derivation algorithm uses the CID prefix, so byte-identical bodies will collide.

**What to do:**
- If the new body is meaningfully different, vary `rkey` explicitly.
- If you want upsert semantics, call `host.delete(did, lexicon, rkey)` first. (Delete API is roadmap, not in v1.)

**Test:** `error paths > RKEY_DUPLICATE — same rkey twice in (did, lexicon)`.

---

## Artifact gaps surfaced and closed during the maturity sprint

The use case wasn't just a test — it was the first thing to actually exercise the package interop. Three real gaps surfaced; all are now closed.

### GAP-001 · Signature shape disagreement (BRIDGED in fixture)

**Symptom:** every published envelope failed `ENVELOPE_MALFORMED` on Stage 1.

**Root cause:** `identity-core`'s `Signer.sign()` produced a `KashEventSignature` with:
- `sig`: base64url-encoded
- `encoding`: `"base64url"` (a field the lexicons schema doesn't know about)
- `kid`: optional

`@kashscript/lexicons/envelope`'s `KashSignature` schema expected:
- `sig`: multibase z-prefix base58btc
- `dst`: literal `kash-record-v1\n`
- `kid`: REQUIRED
- no `encoding` field

So the validator rejected every signature with a "sig does not match format multibase" message.

**Fix applied in this round:** wrote `fixture/signature-bridge.ts` with `toLexiconsShape()` (consumer side) and `toIdentityCoreShape()` (host side). Bridges in both directions via base58 round-trip.

**Upstream fix (recommended):**
- Add `encoding: "multibase"` as a value in `identity-core`'s `SignEventOptions`.
- Teach `verifyEvent` to read multibase-shape signatures.
- Then the bridge becomes a one-time-only adapter, deletable.

**Status:** workaround applied; upstream fix is open work.

---

### GAP-002 · `identity-core` doesn't export `./base64url` (USED ROOT IMPORT)

**Symptom:** `bun test` threw `Cannot find module '@kashscript/identity-core/base64url'`.

**Root cause:** `identity-core` ships `src/base64url.ts` and re-exports via the root `index.ts`, but its `package.json` `exports` map doesn't include `./base64url`. Deep-imports fail.

**Fix applied in this round:** the bridge imports from `@kashscript/identity-core` (root) instead of `@kashscript/identity-core/base64url`.

**Upstream fix (recommended):** add `"./base64url": "./src/base64url.ts"` to `packages/identity-core/package.json` exports map. Two-line edit.

**Status:** workaround applied; upstream fix is open work.

---

### GAP-003 · DID method name mismatch (FIXED IN-PLACE)

**Symptom:** every published envelope failed validation with `"header.did does not match format did-ks"`.

**Root cause:** `identity-core` emits `did:kash:<base58btc-pubkey>` (Ed25519, 43-44 chars). `@kashscript/lexicons` validated against format `did-ks` whose regex was `/^did:kash:[a-z2-7]{32}$/` — entirely different DID method name AND a different encoding alphabet AND a fixed length (32 chars of base32lower = 20 bytes, not 32). The two packages were authored as if the other didn't exist.

**Fix applied in this round (in lexicons source):**
- `packages/lexicons/src/schema.ts:162` — regex changed to `/^did:kash:[1-9A-HJ-NP-Za-km-z]{32,48}$/`.
- `packages/lexicons/src/types.ts:8` — `type DID` brand updated to `` `did:kash:${string}` ``.
- `packages/lexicons/src/envelope.ts:26` — example comment updated.
- `packages/lexicons/src/envelope.ts:120` — `AT_URI_PATTERN` updated to match the new DID format.

The schema-internal format identifier `did-ks` is kept for backward compatibility (it's an opaque name in the schema engine; not user-facing).

**Status:** FIXED. Workspace typecheck remained 19/19 after the change; no downstream code was depending on the old `did:kash:` shape.

---

## Test result after all three gaps closed

```
14 pass
 0 fail
36 expect() calls
```

The flagship Muffler-ingest use case runs end-to-end against the live packages.
