# Flow — Cross-device sign-in

## User flow (what Alice does)

```
┌───────────────────────────────────────────────────────────────┐
│  Day 1 — Device A (laptop)                                    │
│    1. Alice opens Indusland                                    │
│    2. "Create identity"                                        │
│       → Passkey enrollment                                     │
│       → DID derived from pubkey                                │
│       → app persists envelope + key                            │
│    3. Alice posts a few things — all signed by her DID         │
└───────────────────────────────────────────────────────────────┘
                            │
                            │   (Day 2 — Alice gets a new phone)
                            ▼
┌───────────────────────────────────────────────────────────────┐
│  Day 2 — Device B (phone), first launch                       │
│    4. Alice opens Indusland on the phone                       │
│    5. "Sign in" → device-pair flow                             │
│         • iCloud Keychain / Google Password Manager has        │
│           synced her Passkey OR                                │
│         • cross-device WebAuthn (scan QR on laptop)            │
│    6. App receives the identity bundle                         │
│    7. App constructs Signer from the JWK                       │
│       → same DID as laptop                                     │
│    8. Alice posts from the phone — Muffler sees a new record   │
│       under THE SAME DID                                       │
└───────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌───────────────────────────────────────────────────────────────┐
│  Outcome                                                       │
│    • Alice has one identity on two devices.                    │
│    • Her followers see one stream of posts.                    │
│    • Either device alone can sign — losing one doesn't lock    │
│      her out.                                                   │
│    • If a device is lost / stolen, sign-out from another       │
│      device + (separately, via the Recovery use case) rotate   │
│      to a new keypair.                                          │
└───────────────────────────────────────────────────────────────┘
```

The use case test substitutes step 5's UX with an in-memory `exportBundle()` / `importBundle()` — the cryptographic content is identical to what the real platform-managed key sync would deliver.

---

## Data flow (cross-device transfer)

```
                  ┌─────────────────────┐
                  │  Device A (laptop)   │
                  │                       │
                  │  Signer.generate()    │
                  │      │                │
                  │      ▼                │
                  │  privateKey, pubkey   │
                  │      │                │
                  │      ▼                │
                  │  derive did:kash:…    │
                  │      │                │
                  │      ▼                │
                  │  HeadlessStorage:     │
                  │   envelope + JWK      │
                  │      │                │
                  │      ▼                │
                  │  publishes records    │
                  │  → MufflerHost        │
                  └──────────┬──────────┘
                             │
                  exportBundle() emits a
                  portable JSON blob
                             │
        ╔════════════════════╧════════════════════╗
        ║  TRANSFER (out-of-band; user-mediated)   ║
        ║                                          ║
        ║  Real apps:                              ║
        ║    • Apple Keychain key sync             ║
        ║    • Google Password Manager sync        ║
        ║    • WebAuthn cross-device flow (QR)      ║
        ║    • Manual: encrypted backup + import   ║
        ║                                          ║
        ║  Test fixture:                           ║
        ║    • In-memory hand-off                   ║
        ╚════════════════════╤════════════════════╝
                             │
                  importBundle() receives
                  the same JSON blob
                             │
                             ▼
                  ┌─────────────────────┐
                  │  Device B (phone)    │
                  │                       │
                  │  HeadlessStorage:     │
                  │   envelope + JWK      │
                  │      │                │
                  │      ▼                │
                  │  Signer.fromJwk(jwk)  │
                  │      │                │
                  │      ▼                │
                  │  same DID as Device A │
                  │  same pubkey bytes    │
                  │      │                │
                  │      ▼                │
                  │  publishes records    │
                  │  → SAME MufflerHost   │
                  │     (or a different    │
                  │     one — DID is       │
                  │     host-agnostic)     │
                  └──────────────────────┘

  Muffler now sees TWO records from one DID:
      ┌──────────────────────────────────┐
      │ did:kash:…/kash.social.post@v1.0:│
      │   rkey "post-aaa"  (from laptop) │
      │   rkey "post-bbb"  (from phone)  │
      └──────────────────────────────────┘
```

---

## Three round-trip layers in the test

The use case is structured as three independent properties, each tested:

### Layer 1 — Signer JWK round-trip

```
Signer.generate()
   │
   ├─► exportJwk() ──► JsonWebKey-shape JWK
   │                        │
   │                        ▼
   └─◄ Signer.fromJwk(jwk)
       (same DID, same pubkey bytes)
```

Tested without any storage. Just proves the cryptographic primitive is byte-stable.

### Layer 2 — Headless storage round-trip

```
HeadlessIdentityStorage (Device A)
   │
   ├─► write(envelope, jwk)
   ├─► exportBundle() ──► { envelope, jwk } JSON
   │                              │
   │                              ▼
   └─◄ HeadlessIdentityStorage (Device B)
       └─► importBundle({ envelope, jwk })
           └─► readEnvelope() / readKeyJwk() returns identical bytes
```

Tested without any Muffler interaction. Just proves the storage shape round-trips.

### Layer 3 — End-to-end cross-device publish

```
Device A.provision() ──► publishPost() ──► Muffler accepts (DID-A)
                ▼
        exportBundle()
                │
                ▼
Device B.adopt(bundle) ──► publishPost() ──► Muffler accepts (DID-A again)

Assertion: host.listByCollection(DID-A, lexicon).length === 2
```

The cross-device proof: one DID, two devices, two records, one collection on Muffler.

---

## What the data flow does NOT cover

- **Transfer security.** How does the bundle get from A to B safely? In real apps that's iCloud Keychain (Apple-managed E2EE), Google Password Manager, or WebAuthn cross-device (FIDO Alliance protocol). KashScript is agnostic to the transfer mechanism. The bundle itself contains the private key in JWK form — IF the transfer is compromised, the identity is compromised.
- **Device authorization** (which devices count as "Alice's"). A future Multi-Device-Profile lexicon could let Alice formally register a set of devices on her DID Document; bundle transfers would only succeed between registered devices. Out of scope for v1.
- **Revocation per-device.** Sign-out wipes the device but doesn't revoke the underlying keypair. If Alice's phone is stolen + the thief unlocks Indusland but Alice signs out first, the thief is locked out of *her* phone — but if they extracted the JWK before sign-out, they have a forever-key. This is what the Recovery use case (use case #3, social-mofn) is for: rotate the keypair away from a compromised device.
