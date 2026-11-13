# Kash Identity Protocol — Red-Team Audit (Round 1)
**`specs/identity-protocol-audit-r1.md`**

> **Auditor scope:** five adversarial scenarios applied to `specs/identity-protocol.md` v0.1.
> **Outcome:** 9 findings (2 critical, 4 high, 2 medium, 1 informational) → 7 normative patches consolidated into v0.2 of the spec.
> **Severity scale:** *Critical* = silent-permanent identity loss or takeover · *High* = noisy takeover or recoverable lockout · *Medium* = griefing / DoS surface · *Informational* = clarification.

---

## Part I — Vulnerability Report

### Finding 1 — Race-conditioned key rotation after device theft
- **Scenario:** Stolen Phone, key compromise.
- **What v0.1 gets right:** §3 enforces a one-way privilege ladder. The Active Key on the stolen device cannot rotate keys by itself — rotation requires the Management Key.
- **The actual hole:** the spec assumes Management Key lives "warm" but in practice many users will keep Management on the *same* device as Active (single-phone setup). A thief who roots the phone gets both. They can publish an `update` op rotating *out* the Recovery Key before the user notices.
- **Spec gap:** §3.2 has no time-locked guard around management ops that touch the recovery tier. §3.3's `RECOVERY_WINDOW` only protects recovery-vs-recovery races, not management-stripping-recovery races.
- **Severity:** **Critical.** A 5-second-faster thief permanently dispossesses the user.
- **Patch direction:** apply the recovery-window guard to *any* op (regardless of signing tier) that adds, removes, or replaces a Recovery-Key entry. Within that window, a Recovery-Key signature wins by precedence.

### Finding 2 — Total-loss = identity death
- **Scenario:** Total Loss (both phone and paper Recovery Key gone).
- **What v0.1 gets right:** the spec is explicit and honest — §0.2 Non-Goals declares no custodial recovery.
- **The hole:** this is a UX cliff. Any commercial-grade system without *some* logic-only recovery path will lose users every year to fires, floods, and divorces. v0.1 has nothing.
- **Severity:** **Critical** (in product terms; technically by design, but indefensible without an alternative).
- **Patch direction:** introduce **Quorum Recovery** as a fourth, optional, top tier. M-of-N guardian DIDs co-sign a recovery op. No KashScript hosting is required; guardians are themselves `did:kash` holders, and the protocol composes with itself. Sovereignty is preserved because the user picks their own quorum.

### Finding 3 — Offline fork rule is recovery-only
- **Scenario:** Offline Conflict.
- **What v0.1 gets right:** §5.3 (Op Chain Forks) describes resolution for recovery-vs-recovery races.
- **The hole:** the same `prev` can be claimed by **two non-recovery** ops (e.g., the user's offline edit + an automated script's online edit). v0.1 doesn't say which wins. A naive resolver might accept either, producing an inconsistent global view.
- **Severity:** **High.** Silent state divergence. Different verifiers see different DID Documents.
- **Patch direction:** generalize §5.3 into a single sibling-resolution rule. Recovery ops outrank management ops; among same-tier siblings, lowest tip-hash wins. The losing branch is permanently invalid (its descendants do not apply).

### Finding 4 — PDS migration is documented but not discoverable
- **Scenario:** PDS Migration.
- **What v0.1 gets right:** §5.1 explains the migration mechanically (publish an `update` op patching the PDS service endpoint).
- **The hole:** the spec hand-waves over *how third-party apps learn about it*. "Re-resolve naturally on next handshake" is true only if the resolver knows where to fetch the latest op log; if Cloud-A is dark and the witness network isn't mandated, the chain is unreachable.
- **Severity:** **High.** A user who migrates correctly may still appear "offline" to half their apps for days.
- **Patch direction:**
  1. Mandate that the **old PDS** serves a 90-day forwarding response (`410 Gone` + `Forward-To` header) so a single migration is non-fatal.
  2. Mandate **at least three independent witnesses** for any production-grade `did:kash`. Witnesses operate the gossip layer.
  3. Resolvers MUST cache only with a bounded TTL, and SHOULD subscribe to witness webhooks for invalidation.

### Finding 5 — Replay defense is solid but intent-action binding is implicit
- **Scenario:** Malicious App, signature replay across siblings (Duedale, Oreoasis).
- **What v0.1 gets right:** §4.3 already binds `audience`, single-use `nonce`, opaque `intent`, `kid`, and a domain-separation tag. Cross-origin replay is foreclosed; cross-subprotocol replay is foreclosed; nonce reuse is foreclosed.
- **The remaining hole:** `intent` is treated as a human-readable string the Signer surfaces. There's no normative requirement that the *verifier* parse and check it against the actual action being executed. A captured signature with `intent: "post listing"` could in principle authorize a different listing-creation than the one the user saw, if the verifier never re-checks.
- **Severity:** **Medium.** Requires a verifier bug to exploit; defense-in-depth gap.
- **Patch direction:** specify a normative `intent` schema (`<protocol>.<action>:<param-digest>`) and require verifiers to compare the signed `intent` against the action they are about to execute. Mismatch is hard-fail.

### Finding 6 — Witness layer is hinted but not specified
- **Scenario:** raised in Finding 4; deserves its own item.
- **What v0.1 gets right:** §1.5 mentions a witness network as a tamper-evident log.
- **The hole:** no specification of how many witnesses, how they are chosen, what an honest witness must do, or how to detect collusion. A single hostile witness operator could withhold ops.
- **Severity:** **High.** The whole gossip story collapses if witnesses can collude or disappear silently.
- **Patch direction:** add a `witnesses` array to the genesis op — the user-chosen list of witness DIDs. Resolvers MUST query a quorum (≥ ⌈N/2⌉ + 1 of declared witnesses) and reject any chain not co-signed by the quorum. Users SHOULD pick witnesses from independent operators.

### Finding 7 — Resolver cache TOCTOU
- **What v0.1 gets right:** §6 versioning and §1.5 resolution define replay rules.
- **The hole:** apps that cache the DID Document for performance can fall behind a rotation. A revoked active key remains valid in the cache until TTL expires. v0.1 is silent on cache lifetimes.
- **Severity:** **Medium.**
- **Patch direction:** declare a maximum cache TTL (60 s for security-sensitive ops, 24 h for cosmetic data). Witness-driven invalidation is RECOMMENDED.

### Finding 8 — Phishing via intent-rendering UI
- **What v0.1 gets right:** §4.3 says signers must surface `intent` verbatim.
- **The hole:** "verbatim" is a property of the string, not of the rendering. A signer that displays `intent` in tiny gray text under a giant "Approve" button has technically complied. v0.1 doesn't constrain UX.
- **Severity:** **Medium** (UX; not strictly a protocol issue, but the protocol relies on the human consent boundary).
- **Patch direction:** add normative Signer UX rules: (a) `intent` must be the largest text on screen at consent time; (b) `audience` must be displayed unabbreviated; (c) any change to `intent` between announce and sign forces re-prompt.

### Finding 9 — Hash-truncation collision margin (informational)
- **What v0.1 gets right:** §1.1 truncates the genesis-op hash to 20 bytes (160 bits).
- **The hole:** generic 80-bit collision resistance. Adequate for billions of users, but on the edge if `did:kash` ever hosts machines or agents at population scale (10¹²+ identities).
- **Severity:** **Informational.** Not a v0.2 concern; flag for v2.
- **Patch direction:** reserve a `did:kash2:` future-method ID for a 32-byte (256-bit) variant if collision pressure materializes. v0.2 does not act.

---

## Part II — Proposed Patches (v0.2)

The following amendments are normative and applied wholesale to `specs/identity-protocol.md` (version line bumped from 0.1 → 0.2).

### Patch P1 — Recovery-window guard generalized (§3.2 → §3.2.1)
> Any op (any signing tier) whose patch set adds, removes, or replaces an entry of `purpose: "recovery"` is **non-final for `RECOVERY_WINDOW = 72h`**. Within the window, a Recovery Key MAY publish a competing op that supersedes it. Among competing ops, recovery-tier signatures outrank management-tier signatures regardless of timestamp; among same-tier, lowest tip-hash wins.

### Patch P2 — Quorum Recovery (new §3.5)
> Users MAY pre-publish a `set-recovery-quorum` op (signed by Recovery Key) that designates **N guardian DIDs** and a threshold **M ≤ N**. After publication, **M of the N guardians** can co-sign a `quorum-recover` op that replaces the Active, Management, and Recovery key sets wholesale. Guardian attestations are themselves Active-Key signatures over the recovery payload, individually verifiable by replay against each guardian's own DID. Quorum recovery ops are subject to `RECOVERY_WINDOW`.
>
> The hierarchy becomes:
> ```
> Quorum  ─►  Recovery  ─►  Management  ─►  Active
> ```
> Quorum may replace Recovery; Recovery may replace Management; Management may replace Active. The protocol does not host quorum state — guardian DIDs resolve through the same `did:kash` machinery; recursive composition is the whole point.

### Patch P3 — Generalized sibling resolution (§5.3 rewritten)
> Two ops that share a `prev` are siblings. Resolution:
> 1. If their signing tiers differ, the higher tier wins (Quorum > Recovery > Management).
> 2. If tiers match, the op with the lower SHA-256 tip-hash wins.
> The losing branch and all descendants are permanently invalid. Signers SHOULD detect chain advancement past their cached `prev` on reconnect and warn the user before publishing a stale offline op.

### Patch P4 — PDS forwarding + witness gossip (§5.1 expanded; new §5.6)
> **§5.1.1 (forwarding):** A migrating PDS MUST honor `GET /did-log/<did>` with HTTP `410 Gone` and a `Kash-Forward-To: <new-endpoint>` header for at least 90 days post-migration.
>
> **§5.6 (witnesses):** Genesis ops MUST include a `witnesses: <DID[]>` field listing at least three independent witness DIDs. Resolvers MUST verify each newly-fetched op chain co-signed by a strict majority (⌈N/2⌉ + 1) of the declared witnesses; chains that fail this check are rejected even if the cryptographic signature is valid. Witnesses MAY be replaced by a Management-tier op (subject to standard fork rules).

### Patch P5 — Action-bound intent (§4.3 strengthened; new §4.3.1)
> The `intent` string MUST follow the schema:
> ```
> <protocol-namespace>.<action>:<param-digest>
> ```
> e.g., `trade.create-listing:sha256(listing-bytes)` or `auth.signin:realm=duedale.app`.
>
> The verifier MUST compute the param-digest from the actual request payload and compare it byte-for-byte to the digest embedded in the signed `intent`. Mismatch is hard-fail (HTTP 401, no retry). Free-form intent strings are deprecated and MUST be rejected from v0.2 onward.

### Patch P6 — Resolver cache TTL (new §6.3)
> Resolvers MAY cache DID Documents subject to a hard TTL ceiling:
> - Security-sensitive operations (login, key change, transfer): **60 s**.
> - Cosmetic reads (display name, avatar URI): **24 h**.
> Resolvers SHOULD subscribe to witness webhooks for proactive invalidation; failure to do so does not relax the TTL.

### Patch P7 — Signer UX requirements (new §4.5)
> Conformant Signers MUST:
> 1. Render `intent` as the largest typographic element on the consent screen.
> 2. Render `audience` unabbreviated and visually distinct from chrome.
> 3. Re-prompt the user if either field changes between announce and sign.
> 4. Block consent for at least 800 ms after first render to defeat clickjacking.
>
> Non-conformant signers SHALL be marked `untrusted` in the foundry's signer registry.

---

## Part III — Patch Disposition Summary

| Patch | Adds / Updates                                  | Severity Closed | Cross-phase impact                              |
|-------|-------------------------------------------------|-----------------|-------------------------------------------------|
| P1    | §3.2.1 — recovery-tier guard                    | Critical (F1)   | Resolver, Signer, Witness                       |
| P2    | §3.5 — Quorum Recovery                          | Critical (F2)   | Signer (UX), Resolver, Recovery UX phase        |
| P3    | §5.3 — generalized sibling resolution            | High (F3)       | Resolver                                        |
| P4    | §5.1.1 + §5.6 — forwarding + witness mandate    | High (F4 + F6)  | PDS, Resolver, Witness Network                  |
| P5    | §4.3.1 — action-bound intent                    | Medium (F5)     | SDK, all third-party verifiers                  |
| P6    | §6.3 — cache TTL ceilings                       | Medium (F7)     | Resolver, SDK                                   |
| P7    | §4.5 — Signer UX rules                          | Medium (F8)     | Signer phase, foundry signer registry           |

Findings 9 (informational) is filed as a v2 candidate; no v0.2 action.

---

## Part IV — Residual Risks Carried Forward

After v0.2 lands, the audit notes the following classes of risk that *cannot* be closed at the protocol layer alone:

- **Endpoint compromise** (malware on the Signer device) cannot be defeated by the protocol; it is the security floor of any non-HSM scheme.
- **Guardian collusion** (M guardians collude to take over an identity) is a quorum-construction problem the user owns. Recommended product guidance: choose geographically and socially diverse guardians; prefer M ≥ 3.
- **Witness collusion** is bounded by the strict-majority rule, but a user who picks three witnesses run by the same operator effectively has one witness. Recommended product guidance: enforce operator-diversity at registration time.

These residuals are documented in the spec's §0.2 Non-Goals (post-patch) and are scope for product UX, not future protocol revisions.

---

**End of Audit Round 1.** The next audit round (Round 2, post-Phase 2 implementation) will replay the same scenarios against running code and frozen test vectors at `specs/vectors/identity-v1/`.

---

## Addendum — 2026-07-04 — terminology unification (ROADMAP P0)

References to the DID method use the unified label `did:kash` (matching the shipped
runtime, which rejects the retired spelling). Terminology only; the audit findings and
their severities are unchanged.
