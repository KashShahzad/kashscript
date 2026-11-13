# The wallet component — keys first, no account

**`specs/wallet.md` — v1.1 · 2026-10-01 · PL-6, PL-2 · `@kashscript/wallet` (Apache-2.0).**
Decisions: ECOSYSTEM d27, d41, d42 §2, d44, d47 (a, e, f, g), d49 (a, b), d51 · builds on [the holder contract](holder-contract.md), [presentation](presentation.md), [session receipt](session-receipt.md), [thank-you](thank-you.md).

> **What exists, and what does not.** The component is built in source with a headless core, a web adapter, an Expo adapter and a headless mode; `0.1.0-alpha.4` is on npm under `alpha` `[v 10-28, npm view]`. The native half (Swift, Kotlin) is written and **not compiled here**; it compiles in an app's development build (PL-9). **Since PL-2** keys sign ES256 in the secure chip where there is one, and recovery by helpers and succession works ([recovery.md](recovery.md)) — proven in the headless mode, not on a phone. Nothing here has run with a person, at a counter, or on a phone.

It is the embeddable component of d44 and d47(a): the organisation's own wallet inside the portal (web adapter) and the engine of the person's app, *Chakor* (d52, PL-9). It has no screens — trust UI is the design language's grammar (d51, PL-G) — and every word it gives an app is plain and overridable.

## 1. Ports

The core is platform-free TypeScript. An adapter supplies five things:

| Port | What it is | Rule |
|---|---|---|
| `roots` | makes or opens the **hardware root**: `info()`, `publicKey()`, `agree(peer, prompt)` | **No sign method exists.** The root agrees keys and guards everything else (d47(g)(1)). Its public key never leaves the device |
| `store` | opaque names → opaque bytes | receives only ciphertext, except the sealed-vault header |
| `random` | a cryptographic random source | seeded only in the headless mode |
| `now` | unix seconds | injected, so expiry is tested with a clock, never by editing data |
| `transport` | `(request) → response` | the only way out; `null` means the wallet sends nothing |
| `signers` *(PL-2, optional)* | **signing keys in the hardware**: `create()`, `sign(handle, message, prompt)` → DER, `remove(handle)` | separate from the root, which still cannot sign. P-256, ES256, one key per place and per copy of a yes, made in the chip and never leaving it. Absent (web, plain headless): keys are Ed25519, sealed by the root |

The core needs a JavaScript runtime with WebCrypto (Ed25519, ECDSA and ECDH P-256, AES-GCM, HMAC/SHA-256, PBKDF2, AES-KW), as the kernel does. Bun, Node 22 and current browsers have it. **React Native does not**; see §7.

## 2. The sealed store

```
hardware root ──HPKE──▶ vault key ──AES-256-GCM──▶ relationships, keys, log, lists
                                  └─AES-256-GCM──▶ one key per record ──AES-256-GCM──▶ the record
```

- **The vault key** (32 random bytes) is sealed to the root with **HPKE, RFC 9180**, base mode, DHKEM(P-256, HKDF-SHA256) · HKDF-SHA256 · AES-256-GCM, `info` = `kashscript-wallet-vault/1`, `aad` = the header's store name. The header is `{format: "kashscript-wallet-vault/1", sealed: {enc, ct}}` (base64url). Sealing needs only the root's public key; opening needs the root's `agree`, done in the secure chip after one face, fingerprint or screen-lock prompt per unlock. `lock()` wipes it. The implementation passes the RFC's own P-256 test vector.
- **Every record has its own key**, wrapped by the vault key. A sealed value is `iv (12) ‖ ciphertext ‖ tag`, and its associated data is its store name, so a blob moved elsewhere fails to open.
- **Deletion is a crypto-shred (d27.5).** At expiry — the earlier of the expiry signed into the record and the retention its issuer declared — the record's key is deleted first, then its ciphertext. A copy of the ciphertext made earlier opens with nothing the wallet still holds. *Honest limit:* flash storage may keep remnants of deleted files; against someone who images the chip **and** can unlock this phone's root, deletion is as good as the platform's own secure deletion.
- **Names are random slot ids**, never record ids, so the store cannot be asked "do you hold X?".

## 3. Keys

- **Relationship keys** — one per place (d41, d47(g)(2)). **Where the hardware holds the algorithm, they sign in it** (PL-2): with a `signers` port they are P-256 keys made in the secure chip, signing ES256 after the unlock prompt, named by their P-256 `did:kash` (`did:kash:Dn…`); the vault keeps only an opaque handle, sealed. Otherwise they are Ed25519 seeds from `random`, sealed under the vault key, opened only to sign and wiped straight after. **Hardware cannot derive keys, so every key is generated for its place and recorded in this registry** — identity-server's HKDF derivation is for server-side ceremonies only. Every ES256 signature is normalised to low-S before it leaves the wallet.
- **Copy keys** — a yes a person may show verifiers arrives as a batch, one copy per fresh key (presentation §4). A copy is assigned to the first verifier it is shown to and never shown to another; after an import, assignments are rebuilt from the presentation log. **Since KS-Q1 (0.1.0-alpha.4), every SD-JWT a door may read arrives this way** — a receipt, a yes, a decision (d62(d)3) — and only a thank-you stays bound to its place's relationship key, a promise to that relationship alone (d49).
- **A key leaves the device only inside the export's encrypted backup, and only when the holder gives a passphrase** (holder contract §2, v1.2). The hardware root cannot leave its chip.
- `custody` is `hardware` (in the chip; ES256) or `sealed-software` (Ed25519). **A key in the chip is in no backup and no export, ever**; the export reports how many (`keysInChip`), and the copy says why. After a lost phone such keys are succeeded, never copied.
- **Helper keys** — keys this wallet holds as someone else's helper: a pool of 32 sealed Ed25519 keys per person helped, one per place of theirs, never reused ([recovery.md](recovery.md) §4).

## 4. The proof switch (d49(a))

Asked once per place, stored in the vault only, and never pre-ticked (`unset`). It gates **redeeming an offer** (thank-yous included) and **signing a session line**:

| State | What the wallet does |
|---|---|
| `unset` | returns `needs-choice`; sends nothing |
| `off` | sends nothing, signs nothing: the offer expires, the line stays single-signed — pending, never proof |
| `on` | proceeds |

It is in no export, no backup and no request, so a new device asks again. **A decline leaves no trace because nothing is written or sent** — the headless run compares every stored byte and every request before and after. Asks are not gated by the switch: each is its own yes or no.

## 5. What leaves the device

Every request passes a **guard** that knows every identifier the wallet holds — the root's public key, every key in every encoding (DID, JWK `x`, hex), every mailbox token, every relationship's local id — and refuses, before sending, any request carrying one it was not built to carry. It reads inside form fields and base64url segments (JWTs, SD-JWTs), not only raw text. The real transport sends no cookies, no referrer, caches nothing and follows no redirect. There is **no push token, install id or account id** anywhere in the component: a shared push token would let a relay link a person's relationships, so each relationship gets its own random mailbox token for PL-8's relay instead. A source test fails if anything but the transport calls `fetch`.

## 6. The jobs

| Job | Standard | Notes |
|---|---|---|
| **receive** | built on OID4VCI 1.0, pre-authorized, anonymous (holder contract §1) — *not conformant; see `docs/conformance/2026-10-10`* | keys are made only after the issuer hands over a token, so a refused offer changes nothing; every endpoint must be on the issuer's origin; an unlisted sender's record waits in memory for the holder's choice and is marked unlisted |
| **hold** | the holding manifest (§2) | built from what attest computes from the bytes, then checked by `verifyHeldRecord` before storing |
| **present** | built on OID4VP 1.0, by value, DCQL, SD-JWT VC + KB-JWT (presentation §1–§4) — *not conformant; by-reference and encrypted-response requests are not supported* | the ask is checked against its eight rules, its digest, the DCQL query it must equal, its expiry and the public list's copy; one yes answers every need; no record hash is disclosed in v1 |
| **doors** *(KS-Q1)* | a door's rule ([rule.md](rule.md)) — OID4VP 1.0 by value, the rule's own DCQL query, SD-JWT VC + KB-JWT — *not conformant* | `open` verifies the rule from its author's DID, its floor, its digest and that the query is exactly the rule's, then shows the checklist (never a score) over one copy per group — this viewer's own, else a fresh one; `send`, on the person's yes only, posts one `vp_token`: copies never shown to another viewer, the person's own word under a fresh key for this viewer, and a countersigned record only where the wallet holds the key it names (it links, and the view says so, and the log marks it `linkedByHolder`); `no` does nothing. Each sent record is logged as a presentation naming the rule (`ask` = its id, version and hash), so after an export and an import a copy one door saw is still never offered to another. Copies are grouped by their handoff group, or — after an import, which keeps none — by their content |
| **no** | presentation §6 | does nothing — no message, no `access_denied`, no log entry |
| **log** | presentation §5 | holder-side, exported, never sent; excessive-ask notes only if the holder chooses |
| **check** | attest, offline | plain words, who signed, the status with its time, and **what it does not prove**; attest's report is returned beside the words, so a "signed by both" mark is drawn only from a real verification result (d51(g)) |
| **export / import** | `kashscript-holder-export/1` | export sweeps, writes the byte-stable file and self-verifies offline; import verifies offline, drops what has expired, and leaves every switch `unset` |
| **thank-yous** | thank-you spec | single notes, never summed — no total, count or balance in the API; used only with whoever gave them |
| **sessions** | session receipt | `join` gives the place the person's key for it; `cosign` checks the line (chain, parties, the place's signature) before signing; a complete receipt is kept as `countersigned` |
| **recovery** *(PL-2)* | [recovery.md](recovery.md) | **no helpers by default** — none preloaded, no platform key; the person invites people in person and chooses a strict majority of at least two; every place's key signs a helper set in advance, from a different key in each helper's pool; a helper sees a six-digit code and how many places, never a record or a place; a new phone recovers from the saved copy and a quorum's approvals — one short, nothing changes; a place is shown its own succession only when the person chooses. Copies bound to a lost key are never offered |

## 7. Adapters

| Adapter | Root | Store | Label |
|---|---|---|---|
| `@kashscript/wallet/expo` | P-256, key agreement only, in the **Secure Enclave** (CryptoKit `SecureEnclave.P256.KeyAgreement`, `.userPresence`, blob `WhenPasscodeSetThisDeviceOnly`) or the **Android Keystore** (`PURPOSE_AGREE_KEY`, StrongBox first, a 10-second window after the fingerprint, face or screen lock). **Signing keys (PL-2):** separate P-256 keys — CryptoKit `SecureEnclave.P256.Signing` / Keystore `PURPOSE_SIGN` with `SHA256withECDSA`, the same unlock, a software-only key refused — returning DER | app-private files, **out of cloud backups** (iOS Application Support excluded from backup with complete protection; Android `noBackupFilesDir`) | hardware |
| `@kashscript/wallet/web` | WebCrypto P-256 `deriveBits`, non-extractable, in IndexedDB | IndexedDB | **weaker** — any script on the origin can use the key, nothing gates it, clearing site data destroys it. Opening one requires `acknowledgeWeaker: true` |
| `@kashscript/wallet/headless` | WebCrypto, in memory | memory | **practice only** — refused without `practice: true` |

**Neither key type can sign**, so the root cannot sign a record in the hardware itself. **No quiet fallback:** a phone with no screen lock, no secure chip, or Android older than 12 (API 31, which `PURPOSE_AGREE_KEY` needs) gets a plain refusal; those people take part by text message or with a file (d42 §7).

**React Native prerequisites** (for PL-9, ⚠ verify versions then): a WebCrypto implementation — `react-native-quick-crypto`'s coverage table lists every algorithm the wallet uses as supported; a `DecompressionStream` for status lists (without it, status reads *not checked*); and a Metro alias for attest's `node:zlib` fallback. `checkRuntime()` names whatever is missing, and the Expo adapter refuses to start without the required ones.

## 8. The headless mode and the scenarios

`createHeadlessWallet({practice: true, seed, now, transport})` gives a wallet and an `inspect` view of only what its platform could see anyway: the ciphertext it stores and the requests it sends. `runWalletScenarios()` runs the wallet's part of PL-5's set in practice worlds on `.practice.invalid`: **receive, present, decline, export and recover**. *Recover* (PL-2) is the lost phone of PL-5's scenario: records from two places, three helpers enrolled, two of three chosen, the saved copy, a new phone with keys in a practice secure chip (`hardwareSigning: true`), one approval refused as too few, two accepted, the Ed25519 keys succeeded by P-256 keys, old records byte for byte unchanged, the new export verified offline, the café shown only its own claim and carrying its book on, and a fresh ES256 yes verified. After each, the constitution is checked: everything verifies with networking disabled; a decline changes nothing; no identifier crosses between relationships and the root never leaves; nothing is stored in the clear; nothing counts, sums or scores; the switch never leaves; no default word names the ecosystem, a member or a word a person must learn. `bun run headless` prints the report, headed *practice run — not a real-world fact*.

## 9. Honest limits

- **An issuer and a verifier who collude can link a copy** by its holder key — inherent to SD-JWT's holder binding; verifiers alone cannot.
- **A relay sees timing and network addresses** even with one mailbox per relationship.
- **Flash remnants** (§2).
- **Android 8–11 can't hold the root** (§7). An AES Keystore root on older phones would amend d47(g); that is the founder's call.
- **After an import, a place the holder dealt with before sees a new key**, unless the holder shows it the succession (PL-2); the switch is asked again.
- **Recovery needs a copy saved off the phone.** Without one, records and helper sets are both gone. Keys are not people: one person with two phones can enrol twice. A helper who colludes with a place can tell it the person recovered there ([recovery.md](recovery.md) §5).
- **Copies of a yes, and thank-yous, bound to a lost key** still verify as signed but cannot be shown; the issuer gives new ones. Re-issue on a presented succession is not built.
- Batch issuance follows OID4VCI 1.0's `proofs` array; interop with a third-party issuer was first tried on 2026-10-10 against the OpenID Foundation suite (`docs/conformance/2026-10-10`): the wallet **did not pass** — its metadata lookup was corrected that day (RFC 8414 path insertion) and it then stopped at its refusal to send a client identifier. Before that the practice issuer and the wallet had been written together.

## Changelog

| Version | Date | Change |
|---|---|---|
| **v0.1.0-alpha.4** | 2026-10-28 | **Doors (KS-Q1).** `wallet.doors`: `open` checks a door's rule (`@kashscript/predicate`) against the records held and shows the checklist; `send` posts one `vp_token` on the person's yes — copies never shown to another viewer, the own word under a fresh key, a countersigned record only with a key the wallet holds — and logs it; `no` does nothing. **Receive now asks for per-viewer copies of every SD-JWT except a thank-you** (d62(d)3). Headless: a practice desk, and practice issuers that issue further SD-JWT types. **86 tests green.** **Published under `alpha` on 2026-10-28** `[v 10-28, npm view]`; `latest` stays `0.1.0-alpha.1`. |
| **v0.1.0-alpha.1** | 2026-10-01 | **Keys in the secure chip, and recovery by helpers (PL-2).** An optional `signers` port: P-256 signing keys made in the chip, separate from the root, signing ES256 — relationship and copy keys there, a sealed handle in the vault, never in a backup (`keysInChip` says how many). Recovery replaces the stub ([recovery.md](recovery.md)): no helpers by default; invitations in person; 32-key pools so no helper key links two places; a strict majority of at least two; a new phone recovers from the saved copy and a quorum's approvals with a six-digit code, one short changing nothing; a place sees its own succession only when the person shows it. `present` never offers a copy bound to a key the device lacks. Expo: native signing-key functions (Swift, Kotlin — **not compiled here**). Headless: a labelled practice chip; **all five scenarios green, recover included**. **65 tests green**; attest at 256. **Prerelease, not published** — founder-terminal, after identity-core `0.4.0-alpha.0` and attest `0.2.0-alpha.2`. |
| **v0.1.0-alpha.0** | 2026-09-25 | **The wallet component (PL-6).** A headless core: keys first with no account; a hardware root that agrees keys and cannot sign; a vault sealed to it with HPKE (the RFC 9180 P-256 vector passes); one key per record, crypto-shredded at expiry; sealed Ed25519 relationship and copy keys; receive (OID4VCI 1.0 pre-authorized), hold, present (OID4VP, one yes, no disclosure), no (nothing emitted), the presentation log, check (offline, with what it does not prove), export and import of the PL-1 bundle (PL-1's twelve-record and backup vectors import); the proof switch on the device only; thank-yous as single notes; session countersigning; the outbound identifier guard; recovery as an interface only. Adapters: Expo over the `KashWalletRoot` native module (Secure Enclave / Android Keystore, key agreement only, no-backup files — Swift and Kotlin written, **not compiled here**), web (labelled weaker), headless (practice only). The headless scenarios run receive, present, decline and export green, with recover pending until PL-2. **58 tests green**; attest untouched at 208. **Prerelease, not published** — founder-terminal, after attest `0.2.0-alpha.1`. |
