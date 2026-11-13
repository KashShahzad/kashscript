# The session receipt — one encounter, both signatures on every line

**`specs/session-receipt.md` — v1.1 · 2026-10-10 · PL-3, GP-6 · verification in `@kashscript/attest/exchange` (Apache-2.0) · DST `application/vnd.indorania.session-event+json`, owner `indorania` · anchor leaf `kash-session-head-v1\n` (`merkle-leaf`), owner `@kashscript/attest`.**
Decisions: ECOSYSTEM d41, d42 §4, d47(d), d49 · builds on [countersign](countersign.md) and [the holder contract](holder-contract.md).

> **What exists, and what does not.** The format and its verifier are built in attest source (`0.2.0-alpha.1`), with vectors, and **unpublished**. No session host, portal queue or wallet thread exists (PL-8, PL-9, PL-10). Nothing here has run at a counter.
>
> **v1.1 (2026-10-10):** the anchor's second version (§3) is in attest `0.2.0-alpha.4`, **published under the `alpha` tag on 2026-10-10** `[v 10-10, npm view dist-tags]`. No host writes it yet: Indorania's practice anchoring still writes a first-version anchor, with its own RFC 6962 path inside the witness receipt, which attest does not read.

## 0. What a session is

One encounter between a person and an establishment: opened by presence, carrying process and flow lines, closed with both parties holding the same signed record (d42 §4). It is a composition the platform owns, and **Indorania anchors it and never signs one as a party** (d47(d)).

## 1. The lines

Every line is a DSSE envelope, `payloadType` `application/vnd.indorania.session-event+json`, with a canonical (RFC 8785) payload:

`{spec: "indorania.session-event/1", sessionId, seq, prevSha256, kind, atUnix, by, body}`

| Kind | Body |
|---|---|
| `open` | `{profile, parties {establishment, person}, consent {records, asks}, place}` — the one-screen consent, recorded before anything else |
| `presence` | `{}` — the time is the fact |
| `flow` | `{lineItems[]}` — **salted commitments only**, `SHA-256(salt ‖ JCS(item))` |
| `process` | `{step, rule {id, version} \| null}` |
| `disagreement` | `{about, statementSha256}` — a new line about an earlier one; the text stays with the parties |
| `close` | `{total {amount, currency}, lineItemCount, expiresAtUnix}` |

**Both signatures, over the same bytes.** The author (`by`) signs first; the other party's relationship key signs the same PAE bytes — the countersign pattern. **Only the two parties may sign.** Any other key — an operator, a member, Indorania — fails the receipt (`FOREIGN_SIGNER`), whether or not its signature verifies.

**The chain.** `prevSha256` is the SHA-256 of the previous line's payload bytes; the first line's is `SHA-256("indorania-session-genesis" 0x00 sessionId)`. A changed, reordered or deleted line breaks it.

## 2. Profiles — so a coffee does not record what a repair needs

| Profile | Lines allowed (plus open, disagreement, close) | Place in `open` |
|---|---|---|
| `presence+flow` — a coffee | presence, flow | allowed |
| `process+flow` — a repair | process, flow | allowed; no presence line is recorded |
| `presence+process+flow` — a guided day | presence, process, flow | allowed |
| `flow+process` — a grant tranche, no presence | flow, process | **none** |

## 3. The receipt

An unsigned container, `kashscript-session-receipt/1`: `{sessionId, profile, parties {establishment, person}, events[], anchor}`. Every part carries its own signatures and every link is checked by digest, so the container is trusted for nothing. The parties are **pairwise relationship identifiers** — never anyone's global id (d41).

**The total is shared; line items are hashed** (d41, *arrival, not consumption*). The close carries the total both parties signed, and `lineItemCount` must equal the commitments in the flow lines. That a person bought a flat white is provable only if they keep the salt and the item, and choose to show them (`openLineItem`).

**Disagreement is a line, never an arbitration.** Either side may close; neither may delete. A disagreement is a new line naming the one it disputes. Its countersignature acknowledges the disagreement was raised, not that it is right. Disagreements may follow the close.

**The anchor** is `{headSha256, coversSeq, witness}`: the hash of a line, and a transparency-log receipt for it (Rekor or OpenTimestamps, confirmed with `rekor-cli` / `ots`). A log that requires the anchoring host to sign the hash records an **anchoring** signature over a head hash — never a party signature over a line, and never counted as one. Lines after `coversSeq` are reported as not yet anchored.

**The anchor's second version (v1.1, GP-6) — a place in a batch, and nothing of the batch.** An anchoring host anchors complete sessions in batches. The first version says nothing about the batch: its head is checked against its line, and nothing else. The second adds the batch, by addition — the receipt keeps `kashscript-session-receipt/1`, and only the anchor gains a version:

```json
"anchor": { "formatVersion": "kashscript-session-anchor/2", "headSha256": "…", "coversSeq": 5,
            "root": "…", "inclusion": { "treeSize": 5, "leafIndex": 2, "path": ["…", "…", "…"] },
            "witness": { "backend": "rekor", "receipt": { "merkleRoot": "…", … }, "witnessedAt": "…" } }
```

- **One tree per batch**, RFC 6962 §2.1 over SHA-256. Each session's leaf is `SHA-256(0x00 ‖ "kash-session-head-v1\n" ‖ treeSize as 8 bytes, big-endian ‖ head)`. The tag is registered (`merkle-leaf`). The size is in every leaf because an RFC 6962 path alone does not fix a tree's size — a proof for a batch of 5 also passes as one of 6 — and the witness signs only the root.
- **The witness witnesses the root**, once per batch; each receipt carries the root and **its own audit path**, nearest sibling first.
- **The check, offline** (attest `0.2.0-alpha.4`): the head hashes the line it names; the path leads from the head's leaf to `root` (RFC 9162 §2.1.3.2); a witness receipt that names a root (`merkleRoot`, or `digest` for OpenTimestamps) names this one. Any failure is `ANCHOR_MISMATCH`. Whether a public log really holds the root, and when, is still confirmed with `rekor-cli` / `ots`.
- **What it does not establish.** A file can name any root: a one-leaf tree is its own root, so a forger can make an anchor whose path checks against a root of their choosing. The check shows that the path is **consistent with the root the anchor names**, and nothing more. Only a witness gives a root weight, and attest does not read the witness's log. So the report says what stands behind the root — *no public log witnessed that root*, *its receipt names that root; the log itself is not checked here*, or *its receipt names no root* — and a receipt does not need an anchor to be proof of the session.
- **What a checker of one receipt learns about the others:** how many sessions the batch held, its own position in it, and at most ⌈log₂ n⌉ sibling hashes. A sibling is a hash of one other session's leaf, or of several leaves together — so it names another session only to someone who already holds that session's receipt, and then says only that the two were anchored together. **No other session's identifier, keys, head, lines, profile or total is in the receipt.** The flat digest beside it in attest (`computeAnchorMerkleRoot`, the audit bundle's) needs every tip in the batch; this one needs none.
- **A first-version anchor verifies forever**, as before, and now says what it does not prove: *this anchor carries no inclusion proof — that its head is in a witnessed batch is not checked*. An anchor format the verifier does not know has its head checked, raises no fault, and is reported as not known.
- For a host: `sessionAnchorBatch(entries)` gives the root to witness and `anchorFor(i, witness)`, so only the host ever holds the whole batch. The host chooses the order.

**Expiry.** The close carries `expiresAtUnix` (d27.5). A wallet deletes the receipt then, and the holder contract's manifest cannot keep it longer.

## 4. Pending and complete

| State | When | Proof? |
|---|---|---|
| **complete** | closed, and every line signed by both | **yes** |
| **pending** | a line carries one signature, or the session is not closed | **no** — *one signature is pending, never proof* (d41) |

A pending receipt verifies as a file (`ok`) and is labelled pending everywhere: in the report, on the CLI (`PASS (pending — not proof)`), and in the holder export, where only a complete session may be marked `countersigned`.

**Faults** (any fails the receipt): `PARTIES_INVALID` · `EVENT_TYPE_MISMATCH` · `EVENT_MALFORMED` · `SESSION_MISMATCH` · `SEQ_GAP` · `CHAIN_BROKEN` · `FOREIGN_SIGNER` · `BAD_SIGNATURE` · `UNSIGNED_EVENT` · `AUTHOR_NOT_SIGNED` · `FIRST_EVENT_NOT_OPEN` · `OPEN_MISMATCH` · `PROFILE_VIOLATION` · `PLACE_NOT_ALLOWED` · `AFTER_CLOSE` · `DUPLICATE_CLOSE` · `BAD_DISAGREEMENT` · `TOTAL_MALFORMED` · `LINE_COUNT_MISMATCH` · `ANCHOR_MISMATCH`.

## 5. What this does not do

Build the session host, the thread a person sees, or the one-tap establishment flow (PL-8 to PL-10) · record a decline, which has no format ([presentation §6](presentation.md)) · give Indorania a party signature · carry a line item in clear · confirm a public log's own inclusion and time — that stays with `rekor-cli` / `ots`.

## 6. A worked example — checking one receipt in a batch of five

From `packages/attest/test/vectors/anchor` (a simulation: generated once, witness `none`, labelled *practice*). Five complete sessions were anchored together — a coffee, a guided day, PL-3's repair, a grant tranche and an alteration at a tailor's. The repair's receipt keeps its six signed lines from `session-receipt-complete.v1.json` unchanged and carries this anchor, which is everything it holds about the batch:

```json
{ "formatVersion": "kashscript-session-anchor/2",
  "headSha256": "6ae2504eff8182d9ab1e2cf85b8e4f9d9b7e396518e41b8c238dde9d97f55c37", "coversSeq": 5,
  "root": "163b3d005a47482da1cdd1538b66ce04181f5b70f2945c97daa1637fe30ce46a",
  "inclusion": { "treeSize": 5, "leafIndex": 2, "path": [
    "5f2abec853445a5b8c46c2d16e90882bcd35e0ee0cae9a68da794f65ca0c3280",
    "8c5a38dbee7dd92a90d01c00f7fe50514092beff7ffff7f8de497b883c09b335",
    "a576a80c5d03ce634d6d9fad4279d1f33df6a0e1a936f707ef86aca1e1d16226" ] },
  "witness": { "backend": "none", "receipt": { "witnessed": false, "reason": "practice — not witnessed by any public log",
    "merkleRoot": "163b3d005a47482da1cdd1538b66ce04181f5b70f2945c97daa1637fe30ce46a" }, "witnessedAt": null } }
```

The check, with every value recomputed by an independent script (`node:crypto`):

| Step | Computed | Result |
|---|---|---|
| head = SHA-256(line 5's payload bytes) | `6ae2504e…f55c37` | equals `headSha256` |
| leaf = SHA-256(`00` ‖ `kash-session-head-v1\n` ‖ `0000000000000005` ‖ head) | `f2b593b5…fa3888` | — |
| index 2, size 5: sibling on the right, `5f2abec8…` | `39a98121…197b23` | — |
| sibling on the left, `8c5a38db…` | `5d91bfff…6b9fd6` | — |
| sibling on the right, `a576a80c…` | `163b3d00…0ce46a` | equals `root`; the path is used up exactly (`sn` = 0) |
| the witness receipt's `merkleRoot` | `163b3d00…0ce46a` | names this root — and this witness is `none`: the vector is a practice batch, so no public log stands behind the root |

**What the checker saw of the other four sessions:** that there were four, that this receipt is the third leaf, and three hashes. From the host's side (never shipped), they are the grant tranche's leaf, the hash of the coffee's and guided day's leaves together, and the alteration's leaf. **No other session's id, keys, head, lines, profile or total.** A test checks this for all five receipts: none holds another's session id, party keys, head, line payloads or signatures.

The CLI, under Node with the network disabled (`node --require ./test/offline-guard.cjs dist/bin/attest.js verify session-anchored-2.v2.json`):

```
  anchor             : none, covers lines 0–5 — matches
  batch              : leaf index 2 in a batch of 5 — its own path reaches the root this anchor names; no public log witnessed that root; this file holds no other session's id, head or lines
  note               : its path leads from its head, as leaf index 2 in a batch of 5, to the root this anchor names; this receipt holds no other session's id, head or lines
  note               : that root is recorded but no public log witnessed it — nothing outside this file vouches for it
  note               : line items are commitments: what was bought is provable only if its holder keeps the opening and shows it
  what was checked   : both parties' signatures on every line; the total against its hashed line items; the anchor where there is one, and its place in its batch by its own path to the root the anchor names
  does not prove     : what was bought (the line items are hashes); that the goods or service arrived; that any public log saw the anchor — it is recorded only
RESULT: PASS
```

The first-version repair receipt (`session-receipt-complete.v1.json`, attest `alpha.1`) still passes, and now says: `batch : not checked — the anchor carries no inclusion proof this verifier reads`.

## Changelog

| Version | Date | Change |
|---|---|---|
| **v1.1** | 2026-10-10 | **The anchor's second version (GP-6)**, by addition: `kashscript-session-anchor/2`, one RFC 6962 tree per batch, each receipt carrying the root and its own audit path. The leaf tag `kash-session-head-v1\n` was registered first (a new `merkle-leaf` family); the batch's size is in every leaf. First-version anchors verify forever and say they carry no inclusion proof; an unknown anchor format is checked by its head only. §6 is a worked example. Verification in attest `0.2.0-alpha.4`, with new vectors in `test/vectors/anchor`; every earlier vector untouched — **published (`alpha`) 2026-10-10**. |
| **v1** | 2026-09-25 | Lines, both signatures, the chain, the four profiles, salted line items with a shared total, disagreement as a line, the anchor, pending vs complete. Verification in attest `0.2.0-alpha.1`, with vectors — **unpublished**. |
