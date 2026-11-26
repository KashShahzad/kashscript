# ADR-0036: A batch accepted on a sample — one root over many items, a draw from a Bitcoin block named in the stamped seal, exact bounds, and a receipt a person signs

- **Status:** Accepted (PY-5's plan, approved by the founder in plan mode, 2026-11-26)
- **Date:** 2026-11-26
- **Decision drivers:** ECOSYSTEM d96 (a fixed price on an accepted outcome) and d97(d) (USD 0.01 per item in a batch accepted on a sample) · d84 P3 (a rule may say yes or not yet; only a person says no) · d43 (no personal error counts, rankings or watching) · d41 (two signatures or it is not proof) · d49 (a decline leaves no trace) · d27, d28 (verification is free and requires nobody) · d59 (append-only; a version, never a rewrite) · d71 (no format of our own where a standard speaks) · d89 (Bitcoin as a witness) · CLIENT-WALKTHROUGH-2026-11-11 finding 7 (one page, many items, one passkey step) · the prompt PY-5 (PAID-SERVICES-SESSIONS-2026-11-12) and its status note of 2026-11-26 · [`specs/attestation/batch.md`](../../specs/attestation/batch.md).

## Context

d97(d) priced an item in a batch accepted on a sample, and nothing in the kernel could record one. A person answering for thousands of machine outcomes one by one does not happen; a person answering for them all with one click is a rubber stamp, which d96's guard warns the price would reward. Acceptance sampling is the method: check a random sample, accept if few enough fall short, state the bound. Four things had to be settled for the open protocol:

1. **Where the format lives.** PY-5 was written on 2026-11-12, before RW-14 put the attestation record in attest (ADR-0031); it names `predicate` and `lexicons`.
2. **Where the draw comes from.** Neither the asker nor the approver may choose which items are checked — the prompt offered *the trust log's next root or a public beacon*.
3. **How the bound is computed.** Exactly, not by approximation.
4. **How a person, never a rule or a model, answers for it.**

## Decision

1. **The record is `kash.attestation@1.1.0`**: 1.0.0 with an optional `batch` on a receipt, under the same tag. Every 1.0.0 body is a 1.1.0 body; 1.0.0 stays frozen and refuses the member. The receipt's reference is an artefact naming the seal's digest. **attest** holds the format, the arithmetic, the checker and the words (`@kashscript/attest/batch`); **predicate** gains one refusal; **lexicons** is untouched — d59 keeps it for public records an organisation publishes, and a batch acceptance is a held record.
2. **One root, `kash-items/1`:** RFC 6962 over sorted leaves `SHA-256(0x00 ‖ "kash-batch-item-v1\n" ‖ size ‖ salt ‖ item digest)`, equal items refused, the salt kept with the batch and never in a record. The same root fixes a page of many answers, signed in one passkey step, while each item keeps its own record.
3. **The draw comes from Bitcoin, through OpenTimestamps (the founder's ruling).** The seal names a block height ahead of the tip; its digest is stamped; a checker requires a Bitcoin attestation in the stamp below that height, linked headers up to it, each claiming at least 76 bits of work, and at most 144 blocks between. The seed is `SHA-256("kash-batch-draw-v1\n" ‖ seal digest ‖ draw block hash)`; a SHA-256 counter stream, rejection sampling and a partial Fisher–Yates shuffle give the positions.
4. **Exact arithmetic in whole numbers:** the hypergeometric distribution in BigInt; the bound `max {D : P(X ≤ x) > α}`; the plan's limit the bound at `accept`; a checker certifies a stated figure with two evaluations and never searches. At most 1,000,000 items and 10,000 checked.
5. **A person answers:** the counterparty is a key (grade 1 or 2) or a seat or a representative under a mandate — never an organisation's own key, an agent, a desk or a rule (`BATCH_BY_A_PERSON`). More found short than the plan accepts is only *not yet*, saying so; an accepted batch covers its items except those found short.
6. **No copy in this version:** a batch record's natural holder is its issuer, and its size and bound would make a class of one.
7. **predicate refuses** a rule that reads which positions fell short, and a rule about a person that reads anything of a batch but its acceptance (`READS_A_SCORE`, d43).
8. **`attest verify` reads an attestation record of truth** — which until now fell through to *DSSE audit bundle* — and, for a batch, prints the draw recomputed, the bound, the words and what it could not decide; `--batch` checks the items.
9. **`rfc6962Tree` hashes each level concurrently.** Same tree, about five times faster under Web Crypto, measured.
10. **Versions move in source only:** attest `0.3.0-alpha.5`, predicate `0.3.0-alpha.7`. Nothing is published.

## Consequences

### Positive

- A stranger recomputes the draw and the bound from the record alone, offline, with code attest already had for its witnesses: no new dependency, nobody new to trust.
- Neither side alone can steer the draw, and the record shows the batch was fixed before the draw existed.
- The bound is exact, and its meaning is tested: for every true count, the chance it falls below is at most α, summed over the exact distribution.
- The words a person reads before signing are the words the checker prints, from one function, held to the content standard.

### Negative / accepted trade-offs

- **The draw comes hours after sealing** — the price of a source that needs no outside library and no trust in us.
- **An asker who seals many versions and puts the luckiest** defeats the draw; the defence is the asker's engine (it stamps only what it puts, and refuses an ask whose draw is public), and a self-hosted engine's word is the asker's own.
- **A miner could discard a block** to change one draw, at the cost of the block's reward.
- **The work floor is a number with a date.** 76 bits against today's 79.1; a large fall in Bitcoin's difficulty would need it changed.
- **The headers' being Bitcoin's own chain is not checked offline**; the report says so and names the hash to compare.
- **Rebuilding a full batch's root takes about 40 seconds** for a million items; the record's check never builds it.

## Alternatives considered

- **The trust log's next root** — lost: its operator could steer the root through the padding leaves (the founder's ruling of 2026-11-20) and the timing of heads; the operator is us, and the host of hosted books (d28); the log is not running and enters records once per period (KS-Q7).
- **drand, the League of Entropy's beacon** — lost for now: a draw every three seconds, but checking it offline needs BLS12-381 pairings — the kernel's first outside library (P6's supply-chain line, as ADR-0021 judged feelin) or about two thousand lines of our own. It can join as a second `source`.
- **NIST's randomness beacon** — lost: one operator, and its certificate chain to keep.
- **A seed both sides commit to** — lost: the last to reveal can walk away and try again, and two colluding parties choose anything; a public block stops either side alone.
- **A binomial or normal approximation** — lost: the prompt asks for exact bounds, and whole-number arithmetic certifies them cheaply.
- **A new record type for batches** — lost to a new version of the attestation (d59(e)): a batch acceptance is a receipt.

## Dated note

**2026-11-26 — the fresh-session review (PY-5r), before anything was exported or published.**

- **The draw block names its height.** A Bitcoin header does not carry its height, and an OpenTimestamps attestation names one in a number nothing signs; decision 3's checker took the draw block's height from the two together. An asker who edited that number and handed in more headers, or fewer, passed any of the next 144 real blocks as the one the seal named and chose among their draws, at no cost — the work floor never came into it. A sampled batch now carries `coinbase`: the draw block's first transaction and its Merkle path, whose input script names the block's height as BIP34 has required since block 227,931. Passing another block as the named one now takes a block mined at the floor's work with a false height — the cost decision 3 meant. The seal, the stamp and the worked example's seal are unchanged; the conformance file `kash.attestation@1.1.0` was written again once and `attestation.schema.json` regenerated, both recorded. Still Bitcoin, through OpenTimestamps, as the founder ruled; no new dependency.
- **A checker never searches — now true of its faults too.** Decision 4 said so; the `BATCH_PLAN` and `BATCH_BOUND` faults searched for the exact figure, so a record shaped to be wrong held a checker for about four minutes at the caps, and an evaluation with half the draw found short took about 8 seconds (two big products a term). A fault now names a wrong figure *too high* or *too low* from the same two evaluations; each term follows from the one before by one small multiplication and division, and the count at *D* + 1 from the count at *D* by one more. The costliest figure certifies in about 150 ms.
