# I/O contract — Muffler ingest

Each table is the contract a real integration would write code against. Every field shape is stable across the wire; types are pulled from the live source.

---

## `InduslandConsumer.publishPost(body, opts?) → MufflerIngestResult`

### Input

| Field | Type | Required | Notes |
|---|---|---|---|
| `body.text` | `string` | optional | Max 1000 chars (lexicon constraint). |
| `body.media` | `PostMediaRef[]` | optional | Max 8 entries. Each carries `cid` (CIDv1) + `mimeType` + optional dimensions. |
| `body.bento` | `BentoMeta` | optional | Visual metadata: `title?`, `accent?`, `size?`. |
| `body.replyTo` | `RecordRef` | optional | Cross-record reference to the post being replied to. |
| `body.repostOf` | `RecordRef` | optional | Reference to a repost source. |
| `body.mentions` | `string[]` (DIDs) | optional | Up to 16 `did:kash:` identifiers. |
| `body.tags` | `string[]` | optional | Up to 16 tags, lowercase alphanum + `_-`. |
| `body.lang` | `string` (BCP-47) | optional | E.g., `"en"`, `"ur-PK"`. |
| `opts.rkey` | `string` | optional | Override the auto-derived rkey. Useful for "profile" records that must be writable at a stable path. |
| `opts.iatOverride` | `ISO-8601 string` | optional | Override the issued-at timestamp. Useful only for testing. |

All body fields are optional — an empty `kash.social.post` is valid (e.g., a repost with no commentary).

### Output (success)

```ts
{
  ok: true;
  storageKey: string;     // host's internal addressing key (did|lexicon|rkey)
  storedAt: ISO-8601;     // server timestamp of acceptance
  recordCid: string;      // CIDv1 of the canonical body bytes
}
```

### Output (failure)

```ts
{
  ok: false;
  code: MufflerIngestErrorCode;
  message: string;        // diagnostic-only; not stable
  details?: Record<string, unknown>;
}
```

Failure codes are enumerated in `errors.md`.

### Side effects

- Consumer side: increments an internal nonce counter. Does NOT mutate the `Signer`'s key state.
- Host side: writes a record to its in-memory store. In production: persists to DB, optionally federates to follower hosts (out of scope for v1).

### Idempotency posture

- **Same `(did, lexicon, rkey)` twice → `RKEY_DUPLICATE`.** The host treats `rkey` as the deduplication key.
- A consumer that wants "upsert" semantics must call `host.delete(did, lexicon, rkey)` first (API not yet implemented in stub; flagged as roadmap).
- The auto-derived rkey (when `opts.rkey` is omitted) is derived from the CID prefix, making it deterministic for a given body. Two posts with byte-identical bodies would collide.

---

## `MufflerHost.ingest(event) → MufflerIngestResult`

### Input

| Field | Type | Required |
|---|---|---|
| `event.header.did` | `did:kash:...` (43-44 chars) | yes |
| `event.header.lexicon` | `<nsid>@<semver>` | yes |
| `event.header.iat` | ISO-8601 with offset | yes |
| `event.header.nonce` | 32-128 lower-hex chars (≥128 bits entropy) | yes |
| `event.header.cid` | `bafy[a-z2-7]{52,}` | yes |
| `event.header.rkey` | string | optional |
| `event.header.seq` | integer | optional |
| `event.header.prev` | CIDv1 | optional |
| `event.body` | object | yes |
| `event.signature.kid` | verificationMethod id | yes |
| `event.signature.alg` | `"ed25519"` | yes |
| `event.signature.sig` | multibase z-prefix base58btc | yes |
| `event.signature.dst` | `"kash-record-v1\n"` | yes |

### Output

Same `MufflerIngestResult` shape as `publishPost`.

### Verification stages (in order)

1. **Envelope shape** — every required field present, every format pattern matches.
2. **Lexicon known** — `event.header.lexicon` is in the `LexiconRegistry`.
3. **Body schema** — `event.body` matches the lexicon's `bodySchema`.
4. **Lexicon allowlist** (if policy set) — `event.header.lexicon` is in the host's allowlist.
5. **DID decoding** — base58btc decode of `event.header.did.slice("did:kash:".length)` yields a 32-byte pubkey.
6. **DID coherence** — `deriveDid(pubkey) === event.header.did`.
7. **Signature** — `verifyEvent(coreShape, pubkey)` returns true.
8. **DST policy** — `event.signature.dst === host.policy.requiredDst`.
9. **rkey uniqueness** — `(did, lexicon, rkey)` not already stored.

A failure at any stage short-circuits the rest. The first failure determines the result code.

---

## `MufflerHost.get(did, lexicon, rkey?) → MufflerStoredRecord | undefined`

Read-back. Returns `undefined` for misses. No signature re-verification on read — the host trusts records it accepted. Consumers that want re-verification can call `verifyEvent` on the returned event.

---

## `MufflerHost.listByCollection(did, lexicon) → MufflerStoredRecord[]`

Lists every record under `(did, lexicon)`, regardless of rkey. Insertion-order. No pagination in the stub; a real host would paginate by `storedAtIso`.

---

## Signer API used (from `@kashscript/identity-core`)

| Method | I/O |
|---|---|
| `Signer.generate()` → `Promise<Signer>` | Generates a fresh Ed25519 keypair. In production this is `Signer.fromKeyPair(...)` after a WebAuthn ceremony. |
| `signer.did` | `did:kash:<base58btc>` — derived from the public key, stable for the Signer's lifetime. |
| `signer.sign(header, body, opts?)` → `Promise<KashEventSignature>` | Returns the identity-core-shape signature. The use case bridges to lexicons-shape before going on the wire. |
| `signer.publicKey` | Raw 32-byte Ed25519 public key. Used by hosts during DID coherence check. |
| `signer.exportJwk()` | Persistable JWK for secure-enclave storage. Not used in the use case (in-memory keypair). |

---

## Lexicons API used (from `@kashscript/lexicons`)

| Symbol | Purpose |
|---|---|
| `LexiconRegistry` | Host-side: holds registered lexicon definitions. |
| `register(id, bodySchema)` | Convenience overload — parses NSID + semver from the ID string. |
| `validateEvent(event, registry)` | Full envelope + body validation. Returns `{ ok, value } \| { ok: false, errors }`. |
| `KASH_SOCIAL_POST_ID` | Constant: `"kash.social.post@1.0.0"`. |
| `KASH_SOCIAL_POST_BODY_SCHEMA` | The Zod-style schema the body must satisfy. |
