# A batch accepted on a sample

**`specs/attestation/batch.md` — v1.1 · 2026-11-26 · PY-5 (the format half), reviewed in a fresh session (PY-5r) · `kash.attestation@1.1.0`'s `batch`, `@kashscript/attest/batch`, attest `0.3.0-alpha.5` · predicate `0.3.0-alpha.7` — Apache-2.0. Not published.**
Decisions: ECOSYSTEM d96 (the price of a yes) and d97(d) (USD 0.01 per item in a sampled batch) · d84 P3 (a rule may say yes or not yet; only a person says no) · d43 (no personal error counts, rankings or watching) · d41 · d49 · d26 · d27 · d28 · d71 · d89 (Bitcoin as a witness) · the founder's ruling of 2026-11-26 in PY-5's plan: **the draw comes from Bitcoin, through OpenTimestamps** · decision record: [ADR-0036](../../docs/adr/0036-a-batch-accepted-on-a-sample.md) · companions: [the attestation](README.md) · [the trust log](../trust-log.md).

> **What exists.** Built in source with tests: the one root, the seal, the draw, the exact arithmetic, the record's 1.1.0 version and its rules, the stranger's check, the words, `attest verify` for an attestation record, predicate's refusal, four conformance files and two worked examples (one of them waiting on its Bitcoin block, §6). **Not built:** the desk screen, which is `Duedale 2.0`'s (§10); the ceremony that makes an attestation record of truth (the attestation spec's §4.1); the meter's count. Nothing here has run with a person.

## 0. What this is

One person cannot answer for ten thousand machine outcomes one at a time, and a rubber stamp is worse than no approval. Quality engineering's answer is **acceptance sampling**: check a random sample, and accept the batch if few enough fall short, with a stated bound on how many the whole batch can hold. This document gives the open protocol that method, in five parts:

1. **one root over many items**, so the batch is fixed before anyone knows what will be drawn — and so a page of many answers can be signed in one passkey step (CLIENT-WALKTHROUGH finding 7);
2. **a record** of a batch accepted on a sample, a receipt both sides sign;
3. **a draw neither side can choose**, from a Bitcoin block mined after the batch was stamped;
4. **exact arithmetic** for the plan and the bound — no approximation;
5. **a checker** anyone runs offline, and **words** a person reads before signing.

## 1. One root — `kash-items/1`

| Part | What it is |
|---|---|
| **item digest** | SHA-256 of the item's bytes, as the asker delivers them |
| **leaf** | `SHA-256(0x00 ‖ "kash-batch-item-v1\n" ‖ size ‖ salt ‖ item digest)` — the batch's item count as 8 bytes big-endian; a 32-byte salt kept with the batch, never in a record; the item digest. The tag is in attest's registry, family `merkle-leaf` |
| **order** | the leaves sorted ascending; two equal items are refused (give each its own id) |
| **root** | RFC 6962's Merkle tree hash over the leaves in that order |
| **path** | a position's RFC 6962 audit path, nearest sibling first |
| **items file** | `kashscript-batch-items/1`: `{format, salt, digests}` — the salt and every item's digest, in any order |

**Why each part.** The size inside every leaf means a tree of one size never passes as one of another (the session anchor's rule, [session-receipt](../session-receipt.md) §3). The salt means a record's root cannot be used to test a guess about an item; whoever must check items is handed the items file — which lists each item's plain SHA-256, so whoever holds it can test a guess about any item: it goes only to those who may see the items *(said plainly by PY-5r)*. The order is the leaves' own, so the asker cannot move an item into or out of the positions a draw will pick.

**Two uses, one construction.** A sampled batch fixes its items with this root before the draw. A page of many answers — twelve trainees' weeks awaiting one supervisor — fixes the content ids of the records the person is about to sign with the same root, and the engine's passkey step signs that root once. **Each item keeps its own two-signature record**, so each trainee holds a receipt that shows nothing of the other eleven. Carrying the passkey step into each record, so a stranger can check it, is the attestation spec's §4.2 (the grade's evidence), and stays open.

API (`@kashscript/attest/batch`): `itemDigestOf`, `newItemSalt`, `itemLeafHash`, `itemTree` (`root`, `leaves`, `positionOf`, `digestAt`, `path`), `verifyItemPath`, `readBatchItemsFile`, `verifyBatchItems`.

## 2. The record — `kash.attestation@1.1.0`

1.1.0 is 1.0.0 with one optional member, `batch`, on a **receipt** (d59: a new version, appended; the tag `application/vnd.kash.attestation+json` is unchanged). Every 1.0.0 body is a 1.1.0 body; the 1.0.0 shape stays frozen and refuses `batch`. The receipt's `reference` is `{kind: "artefact", sha256: <the seal's digest>}`: what was accepted is the batch the seal fixed.

| `batch` member | What it holds |
|---|---|
| `seal` | what was fixed before the draw (below) |
| `stamp` | the OpenTimestamps proof over the seal's digest, base64 — a sampled batch only |
| `blocks` | the 80-byte Bitcoin headers, hex, from the block the stamp reached up to the draw block — a sampled batch only |
| `coinbase` | `{tx, path}`: the draw block's first transaction, hex, as the block carries it, and its Merkle path, nearest sibling first, each 32 bytes in the byte order the hashing reads them (the order a header stores its root in) — the block's height in its miner's own words (BIP34), since a header carries none. A sampled batch only (PY-5r) |
| `found` | the drawn positions that fell short of the agreed words, ascending |
| `bound` | how many of the batch's items may fall short, at the plan's chance, given what was found (§4) |

| `seal` member | What it holds |
|---|---|
| `format` | `kash-batch-seal/1` |
| `root`, `size` | the `kash-items/1` root and the number of items |
| `plan` | `{sample, accept, alpha: {num, den}, limit}` — how many are checked; the most short items among them with which the batch may still be accepted; the chance the plan accepts as its risk; the plan's limit (§4) |
| `draw` | `{source: "bitcoin/1", height}` — the block whose hash draws, named ahead of the chain's tip. Never on a census |
| `previous` | optional: the digest of an earlier seal over the same items — a new draw says so |

**The seal's digest** is `SHA-256("kash-batch-seal-v1\n" ‖ JCS(seal))`. The stamp is over it and the reference names it.

**A census** — `sample` equal to `size`, every item checked — needs no draw, so it carries no `draw`, stamp, blocks or coinbase; its bound is the count found. A batch smaller than a plan's sample is checked whole, as a census.

**Who signs, and when** — the attestation spec's §2.3, unchanged. The approver answers first; the asker's book signs the same bytes last; one signature is a request, not a record (d41). A batch the approver leaves unanswered, or declines, leaves nothing (d49). **The approver is a person:** a key made for this relationship (grade 1 or 2), or a seat or a representative under a mandate — never an organisation's own key, an agent, a desk or a rule (§5).

**What an accepted batch covers:** every item except those in `found`. A person may accept a batch with short items found, when the plan allows it; those items are not accepted. When more are found than the plan accepts, the batch can only be answered *not yet* (§5).

## 3. The draw — Bitcoin, through OpenTimestamps

**The founder's ruling (2026-11-26):** the draw's seed comes from a Bitcoin block named in the seal and mined after the seal was stamped. Neither side can choose it, nobody new needs to be trusted, and attest already checks OpenTimestamps proofs and Bitcoin headers offline.

**The asker's tooling:**
1. builds the items' root and the plan;
2. reads the chain's tip and names a height ahead of it — far enough for the stamp to land below it (a few hours: 24 blocks in the worked example). How far ahead is the engine's setting;
3. stamps the seal's digest with OpenTimestamps — 32 bytes to the calendars, nothing else;
4. puts the batch to the approver before the named block is mined;
5. once the stamp has reached a block and the named block is mined, fetches the headers between them (`fetchBitcoinHeaders`) and the draw block's first transaction with its Merkle path (`fetchDrawCoinbase`), from any Esplora source — never trusted, always checked.

**What the checker requires** (`checkDrawBlocks`, offline):
- between 2 and 145 headers (`MAX_DRAW_GAP` = 144 blocks, one day);
- each header claims at least **76 bits of work** (`SEED_MIN_WORK_BITS`) and meets its own target — the blocks of November 2026 claim 79.1 (blocks 974281 to 974322, measured `[v 11-26]`), so the floor leaves room for an eight-fold fall in difficulty, while a forged header still costs about a sixth of a block's reward. A number with a date, the founder's to change;
- each header names the one before it by its hash;
- **the last header is the block at the seal's named height, in its own words:** the `coinbase` is a transaction that spends nothing (one input, its outpoint null; its script 2 to 100 bytes; read with and without its witness, never 64 bytes without it), its path from its id reaches the last header's Merkle root, and its input script begins with the height's push as BIP34 has required of every block since 227,931 (`heightPush`: Bitcoin Core's `CScript() << height`) — `checkDrawCoinbase`;
- the stamp is over this seal's digest and holds a Bitcoin attestation at height `named height − (headers − 1)` whose operations reach the first header's Merkle root — so the seal existed before the first header was mined, and so before the draw block.

**Naming the height in the seal** is what stops the asker choosing among the blocks two calendars' commitments landed in: any stamp block below the height will do, and none changes the draw. **It holds only because the draw block names its height** *(PY-5r, the fresh-session review).* A header does not carry its height, and an OpenTimestamps attestation names one in a number nothing signs. Before the coinbase, the checker took the draw block's height from the two together, so an asker who edited that number and handed in more headers, or fewer, passed any of the next 144 real blocks as the named one — and chose among their draws, at no cost. With it, passing another block as the named one takes a block mined at the floor's work with a false height.

**The seed and the positions** ([`batch-draw@1`](tck/batch-draw@1/cases.json) fixes them):
- `seed = SHA-256("kash-batch-draw-v1\n" ‖ seal digest ‖ draw block hash)`, the hash as Bitcoin displays it (double SHA-256 of the header, byte-reversed);
- the stream is `SHA-256(seed ‖ n)` for n = 0, 1, 2, … as four big-endian bytes, each block read as four big-endian 64-bit words, in order;
- a number below *m* takes the next word *w*, and gives *w* mod *m* when *w* is below 2^64 − (2^64 mod *m*) — otherwise the next word — so every number below *m* is equally likely;
- the positions: for i = 0 … sample − 1, j = i + (a number below size − i), swap entries i and j of 0 … size − 1; the first `sample` entries, ascending.

**Not the trust log's next root.** Its operator — us, and the host of hosted books — could steer the root through the padding leaves the founder ruled on 2026-11-20 and through when it signs a head; it is not running yet, and it enters records once per period (KS-Q7). **Not drand** (the League of Entropy's beacon), for now: a draw every three seconds, but checking it offline needs BLS12-381 pairings — the kernel's first outside library, or about two thousand lines of cryptography of our own. It can join later as a second `source` if a same-minute draw is needed.

## 4. The arithmetic — exact

A batch of *N* items holds an unknown number *D* that fall short. A draw of *n*, every set equally likely, finds *X* short; *X* follows the hypergeometric distribution, `P(X = k) = C(D, k) · C(N − D, n − k) / C(N, n)`.

- **The bound** after finding *x*: `max { D : P(X ≤ x; N, D, n) > α }` — so for every *D* above it, a draw this clean comes up at most α of the time. It is the exact one-sided upper confidence bound on a count (Clopper and Pearson's construction, for drawing without replacement). A count of items in this batch — never a rate of anyone's work.
- **The plan's limit** is the bound at *x* = `accept`: if more than `limit` items fell short, the plan would pass the batch at most α of the time (ISO 2859-2 calls the same figure, as a fraction, the limiting quality). Accepting with `found ≤ accept` keeps `bound ≤ limit`.
- **`planFor`** gives the smallest *n* for a wanted limit: with `accept = 0` (none allowed short) or a stated number. The worked example's plan: 140 of 2,000 for a limit of 40 at 1 in 20.
- **Exact:** every count is a whole number (BigInt); α is a fraction of two whole numbers; comparisons cross-multiply. **A checker never searches:** it certifies a stated limit and bound with two evaluations each, at *D* and at *D* + 1, because the chance only falls as *D* grows — and a wrong figure is reported as *too high* or *too low* from the same two, never with a figure found by searching. Searching (`boundOf`, `limitOf`, `planFor`) is the maker's.
- **The cost:** each term of the sum follows from the one before by one multiplication and one exact division by numbers below 10^11, and the count at *D* + 1 follows from the count at *D* and its last term by one more: `count(D + 1) = count(D) − last · (n − x) / (N − D)`, exact because both counts are whole numbers.
- **Limits:** at most 1,000,000 items (`BATCH_MAX_SIZE`) and 10,000 checked (`BATCH_MAX_SAMPLE`); α at most 1 in 2, its denominator at most 1,000,000. Certifying one figure at both caps takes at most about 150 ms, whatever was found; the maker's search for it up to about 5 seconds; rebuilding a full batch's root from its items file about 40 seconds (100,000 items, about 4) — measured on a laptop under Bun, 2026-11-26. *(The fresh-session review, PY-5r: certifying took about 8 seconds with half the draw found short, and a fault's words searched for the exact figure, so a record shaped to be wrong held a checker for about four minutes.)*

[`batch-chance@1`](tck/batch-chance@1/cases.json) gives counts and bounds for twelve cases; the tests check the arithmetic against a count over every subset for every batch of up to 12 items, against Pascal's triangle to 60, and its exact coverage — `P(D > bound) ≤ α`, summed over the exact distribution — for every true *D*.

## 5. The rules

`checkAttestation` runs the rules that need no hashing; `verifyAttestationRecord` adds the rest. Each names its decision.

| Code | The rule | Where |
|---|---|---|
| `BATCH_KIND` | a batch rides only on a receipt | sync |
| `BATCH_REFERENCE` | the reference is an artefact naming the seal's digest | sync (kind) · verify (digest) |
| `BATCH_BY_A_PERSON` | a person answers: a key, not an organisation's own (`did:web`), not grade 3; a counterparty mandate to a seat or a representative, never an agent, a desk or an organisation (d84 P3, d88) | sync · verify (the mandate presented) |
| `BATCH_LIMITS` | a draw no larger than the batch; a plan that accepts fewer than it draws; a chance this format reads | sync |
| `BATCH_CENSUS` | a census carries no draw, stamp, blocks or coinbase; a sampled batch carries all four | sync |
| `BATCH_FOUND` | positions listed once, ascending, inside the batch, no more than drawn — and each one drawn | sync · verify (the draw recomputed) |
| `BATCH_OVER_PLAN` | more found than the plan accepts is only *not yet*, its reasons including `batch-over-plan` — never accepted, never an automatic no (d84 P3); within the plan, no record gives that reason (PY-5r) | sync |
| `BATCH_PLAN` · `BATCH_BOUND` | the plan's limit and the bound are exact; a wrong one is named *too high* or *too low*, never searched for | sync |
| `BATCH_DRAW` | the stamp, the headers, the floor and the draw block's height hold (§3) | verify |

**The check always names what it could not decide** (`notChecked`): that the headers are Bitcoin's own chain (compare the draw block's hash with any copy of the chain); that the batch was put to the approver before its draw was public, and that the asker sealed no other version first (the asker's engine holds those, §9); the items themselves, unless their file is given. A floor lowered by a test is named too.

**No copy in this version.** `copyClaimsOf` refuses a batch record: its natural holder is its issuer, so a copy would be the issuer's own word (the attestation spec's §2.4), and its size and bound would make a class of one. A door reads the record of truth.

**predicate:** a rule reads a batch acceptance only as accepted (node rule 10, as for every attestation). **No rule reads `["batch","found"]`**, and **a rule about a person reads nothing of a batch** but that it was accepted — both refused as `READS_A_SCORE`: what fell short is a count of faults in someone's work (d43). A rule about an organisation's deliveries, or a product, may read the bound.

## 6. The checker, the files and the examples

- **`verifyAttestationRecord(record)`** — both signatures, the rules, and for a batch `verifyBatch`: the seal against the reference, the draw blocks and the draw block's height, the draw recomputed, every found position drawn. Its report carries `batch` (the seal's digest, the drawn positions, the draw block's hash, whether the headers stand).
- **`verifyBatchItems(batch, itemsFile)`** — the items make the seal's root.
- **`attest verify <record> [--batch <items.json>]`** — prints the record, the plan, the draw block, the positions recomputed, what was found, the bound, the items' check, the words (only for a record that checks) and what was not checked. Offline; plain Node; exit 0 on PASS.
- **Conformance files** (`tck/`): [`kash.attestation@1.1.0`](tck/kash.attestation@1.1.0/cases.json) (every synchronous rule's code, with placeholders for the stamp and headers), [`batch-chance@1`](tck/batch-chance@1/cases.json), [`batch-draw@1`](tck/batch-draw@1/cases.json), [`batch-items@1`](tck/batch-items@1/cases.json). Every salt, seed and item is written in; nothing is signed or a key.
- **Worked examples** (`examples/`, generated once by `packages/attest/scripts/batch-example.ts`; keys made and thrown away; every party SAMPLE, every record practice):
  - [`receipt-batch-all/`](examples/receipt-batch-all/) — a census of 40: one found short, which the plan allows; the acceptance does not cover it. Complete.
  - [`receipt-batch-sampled/`](examples/receipt-batch-sampled/) — 2,000 SAMPLE items, 140 drawn, on real Bitcoin blocks. Sealed on 2026-11-26 naming block 977713 (tip 977689 + 24) and stamped at four calendars; the stamp reached block 977693. `bun scripts/batch-example.ts finish` ran on 2026-11-27, once block 977713 was mined: it upgraded the stamp, fetched the 21 headers and the draw block's coinbase, drew 140 positions with block 977713's hash (`00000000000000000000f540c582aa55a2048ccba0f1652a7a79ad02c7484e4e`), had the SAMPLE approver answer (none short, so the bound is 40 of 2,000), signed, and checked the record at the default floor. Both blocks' hashes were compared with two public copies of the chain (mempool.space, blockstream.info) the same day. Complete.

## 7. The words

`batchWords(body, {asker?, voice?})` gives the sentences the desk screen shows before signing (`voice: "approver"`, *you*) and the checker prints (`reader`, *the approver*). One function, so the two never differ. English here; Urdu and Roman Urdu are the screen's copy.

The plan's own example — 10,000 items, 300 checked, none allowed short, 1 in 20:

> You checked 300 of the 10,000 items in Acme's batch. They were chosen by Bitcoin block 977713, mined after the batch was fixed, so neither you nor Acme picked them. All 300 meet the agreed words. The plan: check 300, and accept the batch only if none fall short. If more than 97 of the 10,000 fell short, this plan would pass the batch at most 1 time in 20. If more than 97 of the 10,000 fell short, a draw of 300 as clean as this one would come up at most 1 time in 20. This is not a guarantee: the other 9,700 items were not seen.
>
> It does not show that the items are good — only that you checked these 300 and answered. A draw finds only what a person can see in an item. It says nothing about who made the items.

Over the plan: *3 of the 300 fall short of the agreed words; the plan accepts none, so the batch can only be answered not yet. Tell Acme what to change — only Acme will see it. A new draw needs a new batch.* A census: *You checked every one of the 40 items …* · *This says what was seen in these 40 items, and nothing more.* A new draw: *This is a new draw: these items were sealed once before (seal …).*

The tests hold them to the content standard: a first line a person would say; counts, never percentages; *guarantee* only as *not a guarantee*; no *verified*, *secure*, *score*, *rating*, *trusted*, *reminder* or *urgent*; what it does not prove, in the body; no key and no maker named.

## 8. The edge cases

| Case | What happens |
|---|---|
| a batch smaller than the sample | a census: every item checked; the bound is the count found |
| a defect found | within the plan, the batch may be accepted and those items are not covered; over it, only *not yet*, which a person signs |
| items swapped after the draw | the size-bound, salted root in canonical order fixes every item; a swapped item fails its path (`verifyItemPath`) and the items file (`verifyBatchItems`) |
| drawing again to find a clean sample | one seal has one draw. A new draw is a new seal, a new stamp and a new block, and names the earlier seal in `previous`, which the words say. A seal that hides its predecessor is invisible to the format — the asker's engine, which sees the items, catches it (§9) |
| a rule or a model signing the batch | `BATCH_BY_A_PERSON`; a batch is a receipt, never a decision |
| scoring whoever made the items | no maker field, no breakdown, predicate's refusal; the engine never sums `found` by maker (§10) |
| calling the bound a guarantee | the words, tested |
| a stamp that lands after the named block | the seal cannot draw; the asker seals again — a new batch |
| a stamp whose height was edited, with more or fewer headers, to pass another block as the named one | the draw block's first transaction names its real height, not the seal's: `BATCH_DRAW` (PY-5r) |

## 9. What this does not do, said plainly

- **It cannot see that the headers are Bitcoin's own chain** — only that each carries real work and that the last names the seal's height in its first transaction; a private chain could do both, at the floor's cost per block. Compare the draw block's hash with any copy of the chain.
- **It cannot see that the asker sealed only one version.** An asker who seals many versions of a batch, waits for the draw, and puts the luckiest to the approver defeats the draw. The defence is the asker's engine: it stamps only what it puts to an approver, and refuses an ask whose draw block already exists. A self-hosted engine's word is the asker's own — the same limit as grade 1's (the attestation spec's §2.3).
- **A miner could throw away a block** it found, at the cost of the block's reward, to change one draw. And when two blocks are mined at the named height and one is later dropped, both name that height: the asker could pick either. It happens rarely and nobody chooses when.
- **What fell short travels with the record.** A batch record has no copy in this version, so wherever its holder presents it, `found`, the size and the bound go too: predicate keeps a rule from counting them (§5), but the door's software and whoever runs it hold them *(said plainly by PY-5r)*.
- **Both sides together can choose anything.** The draw stops either side alone; an approver and an asker who collude can make any record, as with any receipt.
- **The label on a mandate is the principal's word** (the attestation spec's §4.8): a key called a seat may be a bot's.
- **A draw finds only what a person can see.** The bound is about items a person checking them would find short.
- **It is slow by design:** the draw comes hours after sealing.

## 10. For the desk screen (`Duedale 2.0`, after PY-4's build)

The screen half of PY-5 builds, on the engine:
- the drawn items one by one, each with *meets the agreed words* or *falls short*, its path checked against the seal's root;
- the bound in words (§7) before the passkey step, and *what this does not prove* in the same type;
- the ceremony that makes the attestation record of truth — the approver first, the asker's book last (the attestation spec's §4.1);
- the engine's rules from §9: stamp only what is put to an approver; refuse an ask whose draw block exists; show the approver a batch withdrawn after its draw; require `previous` when a seal's items overlap an earlier unanswered one;
- never a sum of `found` by maker, never a count of anyone's short items across batches (d43);
- the page of many answers (§1), its passkey step over the root of the records it covers;
- the meter's count of accepted batch items at d97(d)'s price, which is the engine's;
- practice shown as practice, as on every receipt (the content standard's §2, row 21): `batchWords` carries no practice line of its own *(PY-5r)*.

## Changelog

| Version | Date | |
|---|---|---|
| **v1.2** | 2026-11-27 | The worked sampled example finished (§6): block 977713 drew 140 of 2,000, none fell short, the bound is 40, and the record checks at the default floor; its two blocks' hashes match two public copies of the chain. `attest verify --batch` no longer also lists the items under *not checked* once it has checked them (`BATCH_ITEMS_NOT_CHECKED`, exported so a caller that checks the items can drop that line). No format change. |
| **v1.1** | 2026-11-26 | PY-5r, the fresh-session review, before anything was exported or published. **The draw block names its height** (§3): a sampled batch carries `coinbase`, the draw block's first transaction and its Merkle path (BIP34), checked by `checkDrawCoinbase`; without it an edited stamp height let the asker choose among 144 blocks' draws. `BATCH_CENSUS` counts it; `fetchDrawCoinbase` for the maker; the conformance file `kash.attestation@1.1.0` written again once, `attestation.schema.json` regenerated. **A checker never searches** (§4): a wrong limit or bound is named *too high* or *too low*; each term of the sum is one small step, so the costliest figure certifies in about 150 ms (it took 8 seconds, and a record shaped to be wrong held a checker for four minutes). The worked sampled example's seal and stamp are unchanged; its `finish` step now fetches the coinbase. A not yet within the plan does not give the over-the-plan reason (§5). Said plainly: what the items file lets its holder test (§1); what travels with the record, and a fork at the named height (§9); practice on the screen (§10). |
| **v1** | 2026-11-26 | PY-5, the format half, planned and approved in plan mode with the founder's ruling on the draw's source. One root (`kash-items/1`, the leaf tag registered); the seal; the draw from Bitcoin through OpenTimestamps; exact arithmetic; `kash.attestation@1.1.0`'s `batch` and its rules; `verifyBatch`, `verifyBatchItems`; `attest verify` for an attestation record; `batchWords`; predicate's refusal; four conformance files; two worked examples, one waiting on block 977713. attest `0.3.0-alpha.5`, predicate `0.3.0-alpha.7`, **not published**. |
