# Flow — Muffler ingest

## User flow (what the end-user does)

```
┌──────────────────────────────────────────────────────────────────┐
│  1. User opens the Indusland app                                  │
│     → app boots <KashAuthProvider>                                │
│     → provider checks localStorage for an existing identity       │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  2a. No identity yet                  │  2b. Identity exists      │
│      → "Create identity"               │      → "Connect"          │
│      → Passkey enrollment              │      → Passkey assertion  │
│      → DID derived from pubkey         │      → unlock signer      │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  3. User composes a post                                          │
│     → types text + optional media references + optional tags      │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  4. User clicks "Publish"                                         │
│     → Passkey prompt: "Sign post to Muffler?"                      │
│     → user approves (Face ID / Touch ID / Hello)                   │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  5. App posts to Muffler                                          │
│     → success: post appears in user's timeline                     │
│     → failure: typed error code surfaced via toast / inline msg    │
└──────────────────────────────────────────────────────────────────┘
```

The Passkey prompt at step 4 is the only place the user sees biometric UX. Steps 1–3 are normal app interaction; step 5 is HTTP-or-equivalent transport.

---

## Data flow (what bytes move where)

```
┌─────────────────────────┐
│ User keystrokes          │
│ (text, tags, media refs) │
└──────────┬──────────────┘
           │
           ▼
┌──────────────────────────────────────────────┐
│ Consumer builds body                          │
│   body: KashSocialPostBody                     │
│   { text, media[], tags[], bento, ... }        │
└──────────┬──────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────────┐
│ Consumer computes cid                          │
│   bytes  = canonicalizeBytes(body)              │
│   digest = sha256(bytes)                        │
│   cid    = "bafyrei" + base32lower(digest)      │
└──────────┬──────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────────┐
│ Consumer builds header                         │
│   { did, lexicon, iat, nonce, cid, rkey }       │
└──────────┬──────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────────┐
│ identity-core/Signer.sign(header, body)        │
│   payload = DST_bytes ‖ canonicalize({h, b})    │
│   sigBytes = Ed25519.sign(privKey, payload)     │
│   returns: { alg, sig (b64url), encoding,      │
│              dst, kid }                         │
└──────────┬──────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────────┐
│ Bridge: identity-core shape → lexicons shape   │
│   sig: base64url → bytes → "z" + base58        │
│   strip `encoding` field                        │
│   returns: KashSignature                        │
└──────────┬──────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────────┐
│ Wire envelope                                  │
│   KashEvent = { header, body, signature }       │
└──────────┬──────────────────────────────────┘
           │                  (HTTP POST in production;
           │                   in-process function call in the use case)
           ▼
┌──────────────────────────────────────────────┐
│ MufflerHost.ingest(event)                      │
│                                                 │
│  Stage 1: validateEvent (lexicons engine)       │
│    • envelope shape ✓                            │
│    • header.lexicon known to registry ✓          │
│    • body matches KASH_SOCIAL_POST_BODY_SCHEMA ✓ │
│                                                 │
│  Stage 2: lexicon allowlist (if policy set)     │
│                                                 │
│  Stage 3: pubkey derive from did:kash           │
│    decodeBase58(did.slice("did:kash:".length))  │
│                                                 │
│  Stage 4: did re-derive coherence               │
│    deriveDid(pubkey) === header.did ?           │
│                                                 │
│  Stage 5: verify signature                      │
│    bridge lexicons sig → identity-core sig      │
│    verifyEvent(coreShape, pubkey)               │
│                                                 │
│  Stage 6: DST coherence                         │
│    signature.dst === host.policy.requiredDst ?  │
│                                                 │
│  Stage 7: rkey uniqueness                       │
│    (did, lexicon, rkey) not already stored ?    │
│                                                 │
│  Stage 8: store                                 │
│    records.set(storageKey, { event, ts })       │
└──────────┬──────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────────┐
│ MufflerIngestResult                            │
│   ok=true:  { storageKey, storedAt, recordCid } │
│   ok=false: { code, message, details? }         │
└──────────────────────────────────────────────┘
```

---

## Why this shape

- **Body is signed, not just the header.** The signature covers `JCS({header, body})` — mutating either invalidates the signature. The host can't tamper with stored records without losing verifiability.
- **CID is a content hash of the body**, declared in the header. A consumer can independently re-compute the CID from the body and compare. The lexicon engine doesn't recompute the CID — that's a separate integrity check the host can opt into.
- **DST scopes the signature.** `kash-record-v1\n` means "this signature is valid only for record-tier events." A future handshake or trade signature couldn't be reused as a record signature, because their DSTs would differ.
- **rkey is host-chosen by default.** The consumer auto-derives an rkey from the CID prefix to ensure uniqueness within a `(did, lexicon)` collection. The consumer may override (e.g., to write a deterministic "profile" record always at rkey `self`).
