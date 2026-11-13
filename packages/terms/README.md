# @kashscript/terms

> **Agreements with a declared split.** A booking, a pass, a ticket, a bounty, a cohort — as a sealed manifest, a state machine, a split that adds up exactly, and a signed record that it concluded. Pure TypeScript. Apache-2.0.

**It moves nothing and holds no balance.** Money moves on the payer's own rails; Duedale records the declaration and confirms that it arrived. A state here is a stage of the *agreement* — never a label on a person, and never an amount.

```bash
bun add @kashscript/terms
```

## What's in it

| Module | What it does |
|---|---|
| `manifest` | `compileManifest(draft)` validates an agreement and seals it: the canonical (RFC 8785) bytes and `manifestId = kash-trade:0x<keccak-256>`. |
| `fsm` | `transition(state, event, context)` — the agreement's lifecycle as a pure function. Effects are declarations: `sharesDeclared` (put the split in the book), `sharesVoided` (nothing is owed). |
| `splitter` | `declaredSplit(splits, amount)` — the shares to declare, dust-free: they add up to `amount` exactly. Also `declaredGradedSplit` for a partly upheld dispute. Moves nothing. |
| `subscription-thread` | A pass as a thread of linked one-time agreements, one per cycle, each at its own price. |
| `completion-receipt` | A signed record that an agreement concluded — and the gate that lets only its two parties review. |

Three kinds of agreement (`blueprint`): `otdc` (one-time: a booking, a ticket, a bounty), `subscription` (a pass) and `milestone` (a schedule of steps: a cohort).

### The states

`Drafted → Committed → Active → Resolving → Resolved`, with `Disputed`, `Lockout`, `Reverted` and `Cancelled`; a subscription adds `Period_Active`, `Period_Resolving` and `Period_Resolved`. `STATES` is exported, and a test keeps it free of anything that labels a person.

## What a completion receipt does not prove

It proves the **issuer signed a statement about one agreement**: how it ended (`resolved`, `reverted` or `cancelled`), when, and who its two parties were. It does not prove that money moved — `resolved` names the agreement's state, not a payment — nor that the work was good, nor that either party can be relied on. The receipt carries **no price**: the `manifestId` commits to it, so a holder can reveal the manifest if they choose, and a verifier can hash it and match. Verification derives the issuer's key from its `did:kash`, so it needs no one's permission and no network.

The receipt's **tag never changes** — header type `kash.trade.completion`, the domain-separation tag `kash-trade-receipt-v1\n` and the `kash-receipt:` id prefix. The claim inside is `v: 2`. A `v: 1` claim was issued by the retired `@kashscript/trade-core` (removed from the source at AU-11), which still verifies it; this package rejects it.

## Things to know

- **Time is Unix seconds (UTC).** Every instant (`softTimeoutAt`, `concludedAt`, `dueAt`…) and every duration (`periodSeconds`, `cadenceSeconds`) is in seconds, and the caller passes `now` — nothing here reads a clock. A value that looks like milliseconds is refused rather than misread. A wallet checking offline is trusting its own device clock, not this record.
- **A pass of fixed length** (a week, 30 days) uses `cadenceSeconds`. **A calendar-month pass** has no fixed length: give each cycle its own `dueAt` with `cycleLink`.
- **The lockout floor** between an agreement's soft and hard timeouts is `MIN_LOCKOUT_SECONDS` (60 s), a race guard. The manifest declares the real gap, which can be as long as the agreement needs.
- **Shares name `did:kash` parties.** The split declares who each share is *for*; it does not say where it is paid.
- **Hashing is keccak-256** from [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) (MIT), so a stranger can recompute any `manifestId` with any keccak library. It is not NIST SHA3-256.

## Where it came from

`@kashscript/terms` is the agreement kernel of `@kashscript/trade-core`, carried over under ecosystem decision d59 with the scoring, deposit, on-chain and oracle code left behind. See `docs/legal/license-matrix.md` for the retired packages.

## Licence

[Apache-2.0](./LICENSE). Verifying an agreement or a receipt needs no licence and no account.
