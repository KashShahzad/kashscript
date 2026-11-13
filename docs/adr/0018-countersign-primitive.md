# ADR-0018: We build the countersignature as a kernel primitive — a second signature over the same bytes, a per-relationship signing key, and a verifier that needs nobody

- **Status:** Accepted
- **Date:** 2026-09-22
- **Decision drivers:** ECOSYSTEM decision 26 (the countersignature principle, and its build-order consequence); decision 41's *two signatures or it is not proof* and *separate identifiers per relationship*; decision 42's *no member implements a horizontal*; decision 27's five constitutional constraints, in particular rules 1, 3 and 4; decision 28 (never build anything whose verification requires us); decision 44 (a person uses this without learning anybody's name); decision 11 (the honesty doctrine)

> **Not "Duedale ADR-0018".** Four places in this repository — `ROADMAP.md` M7.1,
> `specs/attest.md`, `packages/attest/scripts/bundle-bin.ts` and
> `packages/attest/test/bin-node-smoke.test.ts` — reference the **Duedale** repository's
> ADR-0018 (the attest CLI bin under Node). Those references are qualified as *Duedale
> ADR-0018* as of this change. This document is KashScript's own 0018.

## Context

Decision 26 states the problem in one line: **a record signed only by the party it describes is
self-attestation, and self-attestation is worth approximately zero in the moment it is needed**,
because the adversary in any real dispute is that party and they hold the keys. Decision 41 turned
that into a rule — *two signatures or it is not proof* — and decision 43 carried the same rule into
process evidence.

Nothing in the ecosystem could produce a second signature. `Duedale 2.0/specs/flow-proof-platform.md`
§7 admits it directly: `GrantActorClass` declares `BENEFICIARY` and **no code path ever writes it**;
the recipient's entire participation is a string comparison of a non-secret DID inside a policy gate,
which that repository's own architecture document calls a *"simulated co-sign"*. So every artifact
every member produces today is a one-sided claim, including the ones with the word *proof* on them.

Decision 26 also names the mechanic and the build order: **guest DIDs — a link, one click, signed —
built before consoles, dashboards or billing, because everything above it is theatre without it.** And
decision 42 forbids any member building it locally: it is a horizontal, so it goes in the platform
once or not at all.

Four constraints made this harder than "add a second signature", and each one changed the design:

1. **Separate identifiers per relationship (d41).** A mechanic that makes a counterparty present one
   stable identifier to every requester has built a correlation key across every book in the
   ecosystem — the single most dangerous thing this design could accidentally ship.
2. **The subject holds the key (d27.1)** — but `guest-did.ts` generates keys *server-side* with a
   seven-day cap. Decision 42 lists this as one of two standing gaps in the self-sovereignty claim.
3. **Non-participation stays viable (d27.3).** Declining has to cost nothing, and d41's never-build
   list explicitly forbids *a report naming the individuals who have not confirmed*.
4. **Verification requires nobody (d28).** Including for revocation, which d28 itself calls
   "genuinely hard" and flags as needing an answer before a security review asks for one.

## Decision

We build the countersignature as two halves across two packages, and we make each constitutional
constraint a property of the bytes rather than a promise in a document.

### The artifact: an ordinary DSSE envelope with a second signature

The countersignature is a raw Ed25519 signature over `PAE(payloadType, payload)` — **byte-identical
to what the first signer signed** — appended to the subject envelope's `signatures[]`. Two
consequences we chose deliberately:

- **No new envelope format, and no new DST for the thing being countersigned.** Any existing DSSE
  envelope any member already produces becomes countersignable as it stands. Members add nothing.
- **Both public keys resolve offline.** `did:kash` is self-certifying (ADR-0003), so `parseDid(keyid)`
  yields the key from the identifier itself. The published verifier takes **no `--key` argument at
  all** for this artifact type, which is the strongest available form of d28's rule.

A raw signature carries no time and no context, so the counterparty makes a **second signature with
the same key**: an *acceptance* Kash-Event binding the request id, the request digest, the subject
digest, the key's custody class and `signedAtUnix`. One click, two signatures, one key. Four new DSTs
are registered in `@kashscript/attest/dst` first, by the standing rule: `kash-countersign-request-v1`,
`kash-countersign-v1`, `kash-countersign-withdrawal-v1`, `kash-key-claim-v1`.

The container (`kashscript-countersign/1`) is **unsigned on purpose**: every part inside it carries
its own signature and every binding between the parts is checked by digest, so rewriting the container
can only produce a bundle that fails.

### Where each half lives

**`@kashscript/attest`** owns the format and the verifier. Verification is free (d27.4), attest is the
Apache-2.0 package a stranger installs, and the standalone CLI is already there.
**`@kashscript/identity-server`** owns the ceremony — the request, the one-click signing path, the
per-relationship key, withdrawal and key succession. The dependency runs one way
(identity-server → attest → identity-core) and nothing was forked.

### The four constraints, as implemented

**Per-relationship signing identity.** A wallet derives its signing key with
`HKDF-SHA256(masterSeed, salt)` where `salt = SHA-256("kash-countersign-relationship-v1" ‖
requesterDid ‖ 0x00 ‖ contextLabel)`. The salt is built from **who is asking**, never from who is
answering, so the counterparty contributes no stable input and nothing about them leaks across
requesters. The result is stable *within* a relationship — a holder's own book sees one counterparty
rather than a stranger each time — and unlinkable *across* relationships. Without a wallet, a fresh
key per request, unlinkable by construction. **The request names no counterparty at all**: possession
of a capability secret is the whole address.

**Declining is not recorded. At all.** `declineCountersignRequest` produces no artifact, signs
nothing, writes to no store, and leaves the request's state byte-identical; its only effect is
zeroising the counterparty's local copy of the secret. A decline is therefore indistinguishable from
silence and from an unopened link.

*Why we rejected the alternative the prompt allowed — a recorded but non-aggregatable decline.* The
requester already knows, out of band, which link went to whom, because they sent it. So **any** signal
at time T — hashed, anonymised, bucketed, counted — is joinable on the requester's side back to a
person, and reconstitutes precisely the report d41's never-build list forbids. A count is that report
with one column dropped. The only decline that cannot be aggregated is a decline that does not exist.
The holder learns nothing from a decline, and is not meant to: the **expiry** is how they stop waiting.

**Replay and expiry.** A 32-byte nonce and a window live in the holder-signed request; the acceptance
binds the request digest (which covers both) and declares `signedAtUnix`. A stranger checks
`issuedAtUnix ≤ signedAtUnix ≤ expiresAtUnix` from the bytes alone. The hosted store consumes a
request once, and the window is capped at 90 days so no request becomes a standing claim on somebody.

**Revocation without a centre.** Three layers, none of which is a service. **Expiry does most of the
work** — the only revocation needing no infrastructure is a short window. A **withdrawal is a signed
artifact**: whoever wants to show a request was withdrawn *presents* it, and the verifier checks it
offline (presentation, never lookup). An optional `withdrawalFeed` names **an address the requester
controls, never ours**, and no verifier here fetches it — it is printed as a next step, exactly as the
CLI already does for `rekor-cli` and `ots`.

### The subject-held-key qualification — stated, not finessed

This is the part that must not be allowed to pass unqualified, so it is stated three times: here, in
the module header, and **inside every signature**, as a `keyCustody` field the verifier prints on
every run.

The ceremony's default is a key generated **on the counterparty's own device** and never transmitted
(`subject-generated`). That removes the dependency on `guest-did.ts` for the normal path: the
server-minted seven-day key is now the **fallback** for a counterparty who cannot hold a key — a
feature phone, a relay, a paper form — and carries `delegated-mint`.

**A record signed under a `delegated-mint` key is not subject-held, and stays labelled so
permanently.** We also built the claim path (`claimCountersignKey`): the prior key and a
subject-generated successor sign one body, verifiable offline by anyone holding the pair. It moves
**future** authority to a key the subject holds.

**It cures nothing retroactively, and we will not say that it does.** If somebody else minted the
prior key, they may still hold a copy — and could therefore forge the claim itself. So the claim is
evidence of succession, not evidence that the earlier signature was ever the subject's alone. The
verifier keeps printing `delegated-mint` on that acceptance after a claim, and the test suite asserts
exactly that.

### The link, and the counterparty with no device

The request is a self-contained byte string with three renderings of the same value: a URL fragment
(browsers do not send fragments to the host), a QR payload, and a 26-character Crockford-base32 short
code, dictatable over a voice call and tolerant of the substitutions people make reading one aloud.
Two delivery modes produce **identical signed artifacts** — *hosted* (a short code the requester's own
host exchanges for the request) and *carried* (the whole request travels as bytes; no server anywhere).

**An SMS/USSD/manual-relay path therefore needs a transport, not a second protocol.** We did not build
one: the cost question is founder-terminal. The honest part is that a feature phone cannot hold a key,
so that path is `delegated-mint` and is labelled accordingly.

### No branding in the path

Per decision 44, the ceremony page names nobody: not the parent entity, not a member, not the words
*proof economy* or *standing*. `FORBIDDEN_IN_CEREMONY_COPY` is a list in the source and a test in the
suite. The page has no account, no password, no session, no cookie and **no input of any kind** —
two buttons, asserted by test.

## Consequences

### Positive

- **The ecosystem can produce proof.** d41's rule becomes satisfiable, and d26's build-order
  requirement — before consoles, dashboards or billing — is met.
- **Members add nothing.** Any existing DSSE envelope is countersignable; no member needs a new DST, a
  new format or a consumer app (d42).
- **The strongest offline claim available.** `attest verify` on a countersign bundle takes no key
  material and contacts nothing. Not "we choose not to call home" — there is nothing to call.
- **The dangerous default is closed.** A counterparty cannot accidentally present one identifier to
  every requester, because the salt has no input from them.
- **The honesty doctrine is enforced by bytes.** Custody, the unprovability of withdrawal-absence, and
  the self-declared nature of signing times are all in the verifier's output, not in a footnote a
  marketing page can drop.

### Negative / accepted trade-offs

- **`signedAtUnix` is the signer's own claim.** Inside the window it is *consistent*, not *proven*. A
  lie there is a lie under their own signature, and `attest`'s existing Rekor/OpenTimestamps
  witnessing is the hardening path. We invented nothing of our own for time.
- **Absence of a withdrawal cannot be proven offline.** The verifier says "none presented", never
  "none exists". This is d28's open problem; we have narrowed it with expiry-first, not solved it.
- **The guest path stays honest rather than becoming good.** A counterparty with no device still ends
  up with a key somebody else minted. The label is the fix available today; the real fix is a device.
- **A counterparty without a wallet gets a different DID each time**, so a holder's own book cannot
  recognise a repeat counterparty on that path. Stability within a relationship is what a wallet seed
  buys, and we would rather lose stability than leak linkability.
- **Two signing operations per click**, because a single Ed25519 signature cannot carry both "the same
  bytes as the first signer" and "at this time, under this request".
- **Browser end-to-end is untested.** `renderCountersignPage` returns a string and delegates
  cryptography to a host-supplied module; the tested core is `acceptCountersignRequest`. The page's
  copy, escaping and absence of branding are tested; a real browser ceremony is not.

### The publish is blocked — nothing here is available to anyone yet

`@kashscript/attest@0.1.5` is `latest` on npm and declares `"@kashscript/identity-core":
"workspace:*"`, so `npm i @kashscript/attest` fails for everyone `[v 09-22]`. **A new DST is testable
locally and unusable by any stranger until `0.1.6` is published.** This change bumps the repository to
`attest@0.1.6` and `identity-server@0.2.0` and publishes nothing — publishing is founder-terminal. No
surface may describe this mechanic as available until that publish lands.

## Alternatives considered

- **A new DSSE `payloadType` for countersigned artifacts** — rejected: it would force every member to
  re-wrap payloads they already sign, and the second signature would no longer cover the same bytes as
  the first, which is the whole property.
- **A signed container** — rejected: it invites trusting the container. Unsigned, with every part
  independently signed, means there is nothing to trust.
- **One signature from the counterparty** — impossible: the countersignature must cover bytes fixed
  before the counterparty existed, so time and request-binding have nowhere to live in it.
- **Recording declines anonymously** — rejected; see the reasoning above. Joinable on the requester's
  side, so it reconstitutes a forbidden report.
- **A hosted revocation/status endpoint** — rejected under d28. A status list we operate makes our
  uptime a condition of verification.
- **Reusing `issueGuestDid` as the default signing key** — rejected. It made the mechanic's headline
  property false by construction; it is now the labelled fallback rather than the foundation.
- **Deriving the relationship salt from anything the counterparty supplies** — rejected: any stable
  counterparty-side input is the correlation key d41 exists to prevent.
- **Building the verifier in `identity-server`** — rejected: verification must stay in the free
  package a stranger installs (d27.4), and it would have inverted the dependency.
