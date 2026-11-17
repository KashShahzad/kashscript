# The trust log — issuers, lists and attestations by salted hash, with a public witness for time

- **Status:** v1, built 2026-11-18 (KS-Q4). attest `0.3.0-alpha.0` checks it; kash `0.6.0-alpha.0` writes it. **Not published.**
- **Decision drivers:** ECOSYSTEM d84 P6 (a trust log in Certificate Transparency's manner, before gear 3) · d91(a) (time comes from a witness, never the signer) · d91(f) (the trust list is three assertions with issuer classes) · d91(i) (a receipt issued before the log began carries a witness dated when anchored, never backdated) · d28 (never build anything whose verification requires us) · d27 (hashes, never content) · d5 (OpenTimestamps) · STRATEGY rule 8 (no format of our own where an open one fits).
- **Decision record:** [ADR-0030](../docs/adr/0030-the-trust-log-and-hardened-checking.md). **Code:** `@kashscript/attest/log`, `@kashscript/attest/log-files`, `@kashscript/attest/witness`; `kash log`; `attest log verify`.

## 0. What the log is, and is not

The log is an append-only Merkle tree in the manner of Certificate Transparency (RFC 6962, RFC 9162). Its operator signs a head over it from time to time, and a public witness stamps each head's hash. It answers two questions a stranger asks:

1. **Was this list, this key change or this attestation in the log, and did the log stay one log?** That is answered by an inclusion proof, a consistency proof between heads, and a mirror rebuilt from the entries alone.
2. **By when did it exist?** That is answered by the earliest public witness over the first head that held it, never by anyone's own clock.

It holds **issuers and lists, and attestations by salted hash**. It never holds a person, a presentation, a nonce, an audience, a name, an amount or a record's content. Four entry kinds exist, each a closed shape. A guard refuses everything else before a leaf is made, and every checker runs the same guard on every entry it reads.

**It needs no server of ours.** A log is a folder of files. Any static host serves it, any host mirrors it by copying it, and `attest log verify <dir>` checks it offline.

## 1. The entries

Every entry is a JSON object with `v: 1` and a `kind`. It may carry `backfilled: true` (§6.4). It carries no other field than those listed for its kind.

| Kind | Fields | What it says |
|---|---|---|
| `trust-list` | `listId`, `publisher`, `version`, `issuedAtUnix`, `sha256` | One version of a trust list, by the SHA-256 of the payload bytes its publisher signed (the record's CID basis, [public-records.md](public-records.md) §2.7). |
| `status-list` | `id` (https), `issuer`, `statusPurpose`, `issuedAtUnix`, `sha256` | One version of an issuer's status list, so a withdrawal's time has a witness. `id` is shared by many records, never one per record. |
| `issuer-key` | `issuerId`, `keyid`, `alg` (`Ed25519 · ES256`), `action` (`added · rotated · revoked`), `atUnix`, `listId`, `listVersion` | A key event, as the named version of a trust list says it. |
| `attestation` | `issuer`, `salted`, `claimedAtUnix` | An attestation, by its salted hash (§3). The issuer's own claim of when it was made. |

**The guard** (`logEntryFaults`) checks, and never throws:

- `v` is 1, and `kind` is one of the four;
- every listed field is present and well formed: text is one line of at most 256 characters, hashes are 64 lowercase hex characters, times are whole unix seconds, versions start at 1, the status list's `id` is an https URL;
- no other field is present. A field whose name says it carries what a log never holds is refused as `FORBIDDEN_FIELD`, whatever its value. The names are `holder`, `subject`, `person`, `people`, `user`, `name`, `email`, `phone`, `address`, `presentation`, `vp_token`, `nonce`, `audience`, `relationship`, `record`, `payload`, `content`, `claims`, `disclosures`, `amount`, `total`, `wallet` and `salt`. Any other unknown field is `EXTRA_FIELD`.

**Key events follow the keys a list names** (`kash log add`). A listed key counts, or, for an issuer whose identifier is a `did:kash` with no listed keys, the identifier itself. From one version to the next:

- a key that appears is `added`, or `rotated` when the same issuer lost a key in this version;
- a key that is gone is `revoked`: retired or withdrawn, and the log does not say which;
- a change of standing (`listed · suspended · removed`) is not a key event. It is in the list's version, which the `trust-list` entry hashes.

## 2. The leaf and the tree

The leaf is

```
SHA-256( 0x00 ‖ "kash-log-entry-v1\n" ‖ JCS(entry) )
```

That is RFC 6962's leaf prefix, then the tag registered in attest's registry (family `merkle-leaf`), then the entry in RFC 8785 canonical form. The tree is RFC 9162's, with inclusion proofs (§2.1.3) and consistency proofs (§2.1.4). A mirror recomputes every leaf from the entries alone and reaches the same roots. Without the signed heads, a proof does not fix the tree's size, so sizes come from the checkpoints.

## 3. The salted record hash

An attestation goes in as

```
salted = SHA-256( "kash-log-salt-v1\n" ‖ salt ‖ recordHash )
```

The salt is 32 random bytes per attestation. The issuer keeps it beside the record and hands it to the holder. Without the salt, the entry names no record, and nobody can test a guessed record against the log. With it, the holder proves which record was logged. The salt never enters the log (`salt` is a forbidden field).

## 4. The checkpoint

A checkpoint is a DSSE envelope, `payloadType` **`application/vnd.kash.log-checkpoint+json`** (registered, family `dsse-type`), whose payload carries RFC 9162's tree-head fields:

```json
{
  "format": "kashscript-log-checkpoint/1",
  "logId": "did:kash:<key>/log/<slug>",
  "treeSize": 9,
  "rootHash": "<64 hex>",
  "timestampUnix": 1794945509,
  "previous": { "treeSize": 7, "rootHash": "<64 hex>" }
}
```

- **The log's id names its key.** It is `<did:kash>/log/<slug>`, and only the key that `did:kash` encodes signs its checkpoints. A checker refuses a checkpoint signed by any other key, or one naming another log, before reading anything else in it.
- `previous` is null on the first head and names the head before it on every other. A head whose `previous` the checker does not hold is reported as such.
- `timestampUnix` is **the log's own claim** and never goes backwards. It is shown as the log's time and is never used as the attested time.
- **What a witness stamps** is `checkpointHash`: the SHA-256 of the envelope's payload bytes.

The signer is a seed or a `sign(bytes)` callback to a key service. Both make the same bytes (ADR-0003's first finding, §9).

## 5. The proofs a record carries

Both proofs are self-contained, and checking either fetches nothing.

**`kashscript-log-inclusion/1`** holds `{logId, entry, leafIndex, treeSize, path, checkpoint, witnesses[]}`: one entry, its sibling hashes nearest first, the signed head the path reaches, and the witness files over that head as `{kind: "opentimestamps" | "rfc3161", proofBase64}`. **It carries no other entry.** `kash log proof` makes one against **the first head that held the entry** by default, because only that head's witness can judge the entry's claimed time (§6.2).

**`kashscript-log-consistency/1`** holds `{logId, first, second, path, checkpoints: {first, second}}`: the RFC 9162 proof that the later head extends the earlier, with both signed heads.

`verifyLogInclusion` and `verifyLogConsistency` return a report for every input. `attest verify <file>` detects a checkpoint and either proof.

## 6. Time

### 6.1 Three times, never confused

- **Claimed:** what the entry's author wrote, from an issuer's clock.
- **The log's claim:** the checkpoint's `timestampUnix`, from the operator's clock.
- **Attested:** the earliest **final** public witness over a head that includes the entry. Only this one stands, and it means *existed by*.

### 6.2 The rule with teeth

The log declares `maxBatchDelaySec` in `log.json`: how long an entry may wait for its first witnessed head. **The default is 86,400 seconds, a number the founder may change.**

- An entry that claims a time earlier than the witness of **the first head that held it** by more than that allowance is reported **`CLAIMED_BEFORE_WITNESS`**. Its claimed time is not supported, and the attested time stands. This is how a planted backdated attestation is caught.
- A claim later than the witness, beyond 300 seconds of clock skew, is impossible. It is reported **`CLAIMED_AFTER_WITNESS`** always.
- **Only the first head's witness can judge an early claim.** A later head's witness is an upper bound and nothing more. A checker reads whether a head is the entry's first from the head's own `previous`: the head before it did not hold the entry. A proof against a later head says the claimed time is not judged.

### 6.3 States

| State | Meaning |
|---|---|
| `attested` | A final public witness stands behind the head. |
| `pending` | A witness was asked and has not answered yet, as with an OpenTimestamps proof before its block. No attested time. |
| `unwitnessed` | Only the log's own word. No attested time. |

### 6.4 Backfilled entries (d91(i))

An entry about something that happened **before the log began** says so with `backfilled: true`. Its claimed time is shown, never judged and never relied on: its time is the witness's, dated when it was anchored, and never backdated.

**The mark holds only for a claim from before the log began.** An entry marked backfilled that claims a later time is judged as any other entry, so the mark cannot be a way around §6.2 for exactly the entries the log could have witnessed. The audit takes the log's start as the earlier of `log.json`'s `startedAtUnix` and the first head's attested time. `log.json` is unsigned, so the witness bounds what the operator says. **A proof alone does not carry the log's start.** It takes the mark as written and says so, and `attest log verify <dir>` checks it against the log's files. `kash log add` refuses an attestation whose mark does not fit its claim either way, and marks the list entries it writes itself.

## 7. The files

```
<dir>/log.json                  the descriptor
<dir>/entries/000000.jsonl      entries 0 to 999, one canonical JSON object a line; 000001.jsonl the next thousand
<dir>/checkpoints/<size>.json   the signed head of that size
<dir>/checkpoint.json           a copy of the newest head
<dir>/witness/<size>.ots        an OpenTimestamps proof over that head's hash
<dir>/witness/<size>.tsr        an RFC 3161 token over it; a second of a kind is <size>.2.tsr, and so on
```

`log.json` is `{format: "kashscript-log/1", logId, key, leaf, checkpointType, maxBatchDelaySec, startedAtUnix, origin, note}`. `origin` is the https address the operator serves the folder from, or null until it does. Files are written whole and then moved into place, so a reader never sees half of one. A head is never rewritten, and a witness file is never written over: a second one is numbered.

**Mirroring is copying.** A mirror is honest when its entries rebuild every root the original signed.

## 8. The witnesses

Two public witnesses, which fail differently, as A-List's governance anchors already use them (GOV-5). Each needs only a checkpoint's 32-byte hash.

**OpenTimestamps** (d5). `kash log witness` appends a 16-byte random nonce to the hash, hashes that, and submits the result to the public calendars. At least two of them must accept, so a calendar learns nothing about neighbouring hashes. A proof is `pending` until a calendar's commitment reaches a Bitcoin block. `kash log upgrade` then fetches the attestation. attest reads and writes the `.ots` format byte for byte and recomputes every operation, RIPEMD-160 included, offline. **A proof is final only where the checker holds the block's 80-byte header**: its proof of work (at least 64 bits claimed) and its merkle root are checked, and `--header` hands one in. Without it, the proof names its block and stays `unchecked`.

**RFC 3161.** A `TimeStampReq` over the hash, with a nonce, to an authority. DigiCert's public one is the default URL, as GOV-5 uses it. attest reads the token itself: its status, its imprint (it must stamp this hash, as SHA-256), its time, serial, nonce and the authority's name. **The token's CMS signature and certificate chain are checked by `openssl ts -verify`** against a root the caller names (`--tsa-root`), as of the token's own time, with that root as the only trust anchor. attest prints the root's fingerprint to compare with the authority's published one. Without the check, the token's time is read and never relied on (`unchecked`).

**Going online.** Only `kash log witness` and `kash log upgrade` open a socket, and each says so before its first request. What leaves the machine is a 32-byte hash, a calendar's own commitment, or a `TimeStampReq` over the hash. All checking is offline.

## 9. The writer and the key

`openTrustLog({logId, store, signer, maxBatchDelaySec})` is pure: a `LogStore` the caller provides, a signer, and Web Crypto. `kash log` puts a folder behind the store (`FileLogStore`), an engine can put its database, and a test puts memory. It refuses an entry the guard refuses before any leaf is made. It signs a head only over entries it holds, and it never lets a head's time go backwards.

The log's key is the scheme's **publisher key**, the same role that signs trust lists (d62(d)5): `kash station init --name publisher`. It signs by seed or through a `sign(bytes)` callback to a key service. The callback's answer is verified under the key's public half before it is used, and both paths produce identical bytes.

| Command | What it does | Online |
|---|---|---|
| `kash log init <dir> --name <slug>` | writes `log.json` naming the publisher key, with optional `--max-batch-delay` and `--origin` | no |
| `kash log add <dir> <file>…` | a signed trust list becomes its version plus its key events (`--previous` names the version the log holds), a signed status list becomes its version, and attestation entries come as JSON or `.jsonl`; the whole batch is checked first, and duplicates are refused | no |
| `kash log checkpoint <dir>` | signs the head with the publisher key; with nothing new, it signs nothing | no |
| `kash log witness <dir>` | sends the head's hash to OpenTimestamps, and with `--tsa [url]` to an RFC 3161 authority beside it (`--no-ots` skips the first); `--tsa-root` keeps a token only if openssl verifies it | **yes** |
| `kash log upgrade <dir>` | asks the calendars a pending proof names for their Bitcoin attestation | **yes** |
| `kash log proof <dir> <index>` | prints the inclusion proof against the entry's first head, with that head's witnesses | no |

## 10. The audit — `attest log verify <dir> [--mirror <dir>] [--header <file>]… [--tsa-root <pem>]`

It rebuilds the tree from `entries/` alone, then checks every checkpoint against it. For each head it checks the signature by the log's key, the root, the head before it, the time order, the RFC 9162 consistency proof from the head before, and each witness file's digest. It then judges every entry's claimed time against its first head's witness (§6). Every fault is named:

`DESCRIPTOR_MALFORMED` · `ENTRY_REFUSED` · `CHECKPOINT_INVALID` · `CHECKPOINT_FOREIGN` · `SIZE_BEYOND_ENTRIES` · `ROOT_MISMATCH` · `PREVIOUS_MISMATCH` · `TIMESTAMP_REGRESSION` · `CONSISTENCY_FAILED` · `WITNESS_DIGEST_MISMATCH` · `WITNESS_INVALID` · `SPLIT_VIEW` · `MIRROR_DESCRIPTOR_DIFFERS` · `MIRROR_ROOT_MISMATCH` · `MIRROR_ENTRY_REFUSED` · `MIRROR_CHECKPOINT_INVALID`

A time finding (§6.2) is reported beside the faults. **The log can be whole while a claim in it is not supported.**

## 11. What this version cannot catch, said plainly

- **No gossip.** Mirrors do not compare heads with each other yet. A checker that holds two heads of one size with different roots reports `SPLIT_VIEW`. **A checker shown only one view cannot see a split view shown to someone else.** Mirrors, and `--mirror`, are the first defence.
- **Leaving things out.** The log proves what it holds. It cannot show that an issuer logged every attestation it made, or that the operator logged every list it was handed.
- **`log.json` is unsigned.** Its `startedAtUnix` and `maxBatchDelaySec` are the operator's word, and the first head's witness bounds the start (§6.4).
- **An RFC 3161 time rests on openssl and on the root the checker names.** An OpenTimestamps time rests on a block header the checker holds. Without them, a time is read and never relied on.
- **The log says nothing about whether a record is true.** It holds lists and hashes, never a record, so it cannot show what a record says or who holds it.

## 12. Crypto agility — designed, not built

attest's `SIGNATURE_PROFILES` (`./signing`) is the one registry of what may sign. Each profile names its key type, its `did:kash` multicodec, its JOSE `alg`, its Kash-Event `alg`, each family's signature encoding and its hash. Two rows are live, `Ed25519` and `ES256`. **`ML-DSA-65` (FIPS 204, security category 3) is reserved**: it is named so nobody reuses the name, and it verifies nothing. `ALLOWED_JOSE_ALGS` and `ALLOWED_EVENT_ALGS` derive from the live rows, so a header naming anything else, `none` included, is refused before a key is touched.

**How ML-DSA joins, when a reason comes:**

1. Its row goes live, with its own multicodec and therefore its own `did:kash` prefix.
2. Its verifier is added behind the same resolver, so the algorithm still comes from the key, never the header.
3. A hybrid is a composite profile over two live rows: both signatures, and both must verify.

**What does not change:** the registry's tags, the leaf, the checkpoint format, and every proof. A log may hold heads signed under different profiles, because each head names its signer by id.

## 13. Conformance vectors

`packages/attest/test/vectors/log/` holds a log of nine entries over three heads, the planted backdated attestation and a backfilled one, inclusion and consistency proofs, an honest mirror, five tampered copies (altered, removed, reordered, a stranger's head, a split view), and real RFC 3161 tokens from a SAMPLE authority whose root is kept as `sample-tsa-root.crt`. They were generated once, and the keys are gone. `packages/attest/test/vectors/witness/` holds the OpenTimestamps project's example proof and a real proof from the decision log's anchors, each with its Bitcoin header, and a real DigiCert token.

## Changelog

| Version | Date | Change |
|---|---|---|
| **v1** | 2026-11-18 | KS-Q4. The four entries and the guard; the leaf and the salted hash; the checkpoint; the inclusion and consistency proofs; the files and the audit; the time verdict with `CLAIMED_BEFORE_WITNESS` and `CLAIMED_AFTER_WITNESS`; backfilled entries, held only before the log began; OpenTimestamps and RFC 3161 witnesses; `kash log`; the profile registry with ML-DSA-65 reserved. attest `0.3.0-alpha.0`, kash `0.6.0-alpha.0`. **Not published.** |
