# `@kashscript/identity-server` — Red-Team Audit (Round 1)
**`specs/identity-server-audit-r1.md`**

> **Auditor scope:** the agent-token MCP-OAuth profile (`agent/token.ts` mint/verify, `jwks.ts`,
> `agent/resource.ts`) + the `identity-core` DID/base58 substrate, verified with adversarial probes against
> the real source (M6, ADR-0016). **Outcome:** 6 findings (1 **Critical**, 3 Medium, 1 Low, 1 Info). 3 fixed
> this round (F1, F2, F5); F3, F4, F6 logged with patch directions.
> **Severity scale:** *Critical* = authentication bypass / owner impersonation · *Medium* = trust/replay gap
> · *Low/Info* = hardening.

The classic dimensions are solid — `alg:none`/HS256/`typ` are pinned and rejected; the self-certifying
`did:kash` default derives the verify key from `sub` and is genuinely unforgeable. Every serious issue is
in the **key ↔ claim binding** on the JWKS / explicit-key paths.

---

## Part I — Findings

### F1 — JWKS/explicit-key signer is never bound to `sub`: owner impersonation · **CRITICAL** · CODE-BUG · **FIXED r1**
- **Location:** `agent/token.ts` key resolution (JWKS branch) + owner-binding extraction.
- **Scenario:** a resource server verifies with a multi-tenant JWKS. Any party whose key is in that JWKS
  mints a token with `sub` = **victim owner**, `act.sub` = attacker, `header.kid` = **attacker's own kid**,
  signed with the **attacker's** key. Verify returned `ok:true` with `ownerBinding.owner = victim`. **Proven.**
- **The hole:** the JWKS branch selected the key **solely by attacker-controlled `header.kid`** and never
  checked it corresponded to `claims.sub`. (The self-certifying default is safe *because* it derives from
  `sub`; the JWKS/explicit branches abandoned that invariant.)
- **Fix:** the JWKS branch now resolves the key by the **owner did (`claims.sub`)**, never `header.kid`. This
  binds signer→owner and stays rotation-safe (a rotated owner publishes their current key under `kid = sub`
  in the JWKS). Regression test: "refuses owner impersonation via a multi-tenant JWKS" +
  "a genuine token still verifies via JWKS keyed by the owner did." The explicit `opts.publicKey` path is
  documented as caller-asserted ("this key is `sub`'s").

### F2 — `sub` / `act.sub` binding accepts arbitrary non-DID strings · **Medium** · CODE-BUG · **FIXED r1**
- **The hole:** verify gated `sub`/`act.sub` through `isDidString`, which accepted **any non-empty string**
  — the RFC 8693 delegation identity a resource server keys authorization/audit on could be `"admin"`.
- **Fix:** `isDidString` now requires a well-formed `did:kash` (`isKashDid`), applied to both `sub` and
  `act.sub`. A non-did `sub` fails `MALFORMED_CLAIMS` *before* any signature work. Regression test added.

### F3 — No issuer trust by default · **Medium** · DESIGN-GAP · LOGGED
- **The hole:** `iss` is free-form and validated only when `expectedIssuer` is passed; RFC 9068 §4 requires
  the RS to validate `iss`.
- **Disposition — LOGGED.** With F1 fixed (signer bound to `sub`), impersonation is closed even without
  issuer trust. **Patch direction:** make `expectedIssuer` mandatory on the hosted/JWKS path (throw if a
  JWKS is supplied without one), or require `iss === sub` on the self-certifying path.

### F4 — No replay/revocation; `jti` minted-not-consumed; `cnf.jkt` ignored · **Medium** · DESIGN-GAP · LOGGED
- **The hole:** a captured token replays freely within `exp`; a revoked DID's tokens keep verifying to
  natural expiry; `cnf.jkt` (DPoP proof-of-possession) is carried but never enforced.
- **Disposition — LOGGED.** **Patch direction:** add optional `isRevoked(did)` / `jtiSeen(jti)` hooks to
  `VerifyAgentTokenOptions` short-circuiting to new `REVOKED`/`REPLAYED` reasons; enforce or reject `cnf.jkt`
  rather than silently ignoring it. (Short token TTLs are the current mitigation.)

### F5 — Unbounded clock skew silently disables expiry · **Low** · DESIGN-GAP · **FIXED r1**
- **The hole:** `clockSkewSeconds` had no ceiling; a large (mis-set / hostile-env) value accepted
  long-expired tokens. **Proven:** a 200 000 s skew accepted a token expired ~99 000 s ago.
- **Fix:** skew is clamped to `[0, 300]` s (common JWT guidance). Regression test:
  "clamps an over-large clock skew so a long-expired token is still rejected."

### F6 — `iat` required but never sanity-checked · **Info** · SPEC-GAP · LOGGED
- **The hole:** a far-future `iat` with no `nbf` verifies immediately; nothing ties `iat <= now (+skew)`.
- **Disposition — LOGGED.** Minor; optionally reject `iat > now + skew`.

---

## Part II — Disposition Summary

| Finding | Severity | Disposition |
|---|---|---|
| F1 owner impersonation (JWKS) | **Critical** | **FIXED r1** (resolve key by `sub`) + tests |
| F2 non-DID sub/act.sub | Medium | **FIXED r1** (isKashDid) + test |
| F3 issuer trust optional | Medium | LOGGED (mandatory-issuer on JWKS path) |
| F4 replay / revocation | Medium | LOGGED (add hooks; enforce cnf) |
| F5 unbounded clock skew | Low | **FIXED r1** (clamp ≤300s) + test |
| F6 iat plausibility | Info | LOGGED |

## Part III — What the package gets right
- **Algorithm confusion — solid.** `alg` pinned to `EdDSA`, `typ` to `at+jwt`, before any signature work;
  `alg:none`/HS256/`typ:JWT` all rejected. No HS/asymmetric polymorphism.
- **Self-certifying default — solid.** Deriving the verify key from `parseDid(sub)` makes owner-forgery
  impossible on that path (F1 was the *other two* key sources).
- **Audience (RFC 8707) — solid.** Mint + verify use identical `canonicalizeResourceUri`; array `aud`
  handled; empty `aud` fails closed; no substring/prefix matching.
- **Injection — solid.** `JSON.parse` over base64url; `__proto__` as a claim does not pollute; `additionalClaims`
  cannot override mandatory claims (spread first). JWKS parsing rejects private `d` scalars + non-Ed25519.
- **PKCE — solid.** S256-only, constant-time challenge compare. `nbf` enforced with correct skew direction.

## Part IV — Residual Risks Carried Forward
- **Replay / revocation (F4)** cannot be closed without the caller-supplied hooks — until then, keep token
  TTLs short.
- **Multi-issuer JWKS trust (F3)** — the fail-closed "issuer required on JWKS path" is the next round's change.

---
**End of Round 1.** F1 (the authentication bypass) fixed and tested first; F2/F5 fixed with tests;
F3/F4/F6 carried with patch directions.
