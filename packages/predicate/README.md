# @kashscript/predicate — the rule engine for doors

**Apache-2.0. Pure and deterministic: no clock, no network, no model.** `0.1.0-alpha.0` — on npm under `alpha` (`bun add @kashscript/predicate@alpha`).

A door is anywhere someone decides on evidence (ECOSYSTEM d84). It publishes a **rule**; the person's side checks it first, **as a checklist and never a score**; the person sends a **packet** by choice, a copy per viewer; the desk checks it free and **routes** it; the **decision** comes back as a receipt the person keeps.

| Subpath | What it does |
|---|---|
| `@kashscript/predicate/rule` | `validateRule` (the floor: P4's second rule, node rules 10–11, d43), `ruleHash`, `signRule` / `readRule` (DSSE, by the author), `ruleRequest` / `openRuleRequest` (OpenID4VP `direct_post`), sealed thresholds for private rules |
| `@kashscript/predicate/checklist` | `checklist(rule, heldReceipts, {asOf, …})` — per criterion: **answered**, **missing** (and who the rule accepts), **own-word** or **sealed**. No number anywhere |
| `@kashscript/predicate/packet` | `buildPacket` (one `vp_token`: SD-JWT copies with KB-JWT, the person's own word, `kash-artifact` with its binding) and `checkPacket` (the desk's free, offline check) |
| `@kashscript/predicate/route` | `route` → `automatic-yes`, `not-yet` or `to-a-person`. **Never a refusal** |
| `@kashscript/predicate/decision` | `validateDecision`, `decisionFromRoute`, `decidePerson` (a named person, their seat's signature), `issueDecision` (SD-JWT VC to the person), `readDecision` |
| `@kashscript/predicate/dcql` | OpenID4VP 1.0 DCQL: claims path pointers, matching, a rule's whole `dcql_query` |
| `@kashscript/predicate/feel` | the FEEL subset — DMN literal expressions for counts, dates, sums and thresholds; exact decimals; refuses what it does not hold. 867 DMN TCK cases claimed, 1,006 refused, none wrong |
| `@kashscript/predicate/fixtures` | practice rules: hiring, internship credit, a CPD cycle, income — and one planted violation per refusal |

```ts
import { readRule, ruleRequest, checklist, buildPacket, checkPacket, route, decisionFromRoute } from "@kashscript/predicate";

const rule = await readRule(signedRuleEnvelope);                  // verifies offline from its author's DID
const req = ruleRequest(rule, { nonce, responseUri });            // the door's request
const list = await checklist(rule, heldReceipts, { asOf, trustLists });   // the person's side, first
const packet = await buildPacket({ rule, request: req, entries, iatUnix });  // on the person's yes
const check = await checkPacket({ rule, request: req, vp_token: packet.vp_token, ctx: { trustLists }, asOf });
const routed = await route(rule, check, { asOf });               // automatic-yes | not-yet | to-a-person
if (routed.route !== "to-a-person") decisionFromRoute(routed, rule, { decidedAt: asOf });
```

Specs: [`specs/rule.md`](../../specs/rule.md) · [`specs/decision.md`](../../specs/decision.md) · [`specs/feel-subset.md`](../../specs/feel-subset.md) · [ADR-0021](../../docs/adr/0021-rule-and-decision.md).

**Size** (browser, minified): 163.4 KiB, 54.6 KiB gzipped, with attest's verification inside; `/feel` alone 36.2 KiB, 11.9 KiB gzipped.

**Depends on** `@kashscript/attest`, `@kashscript/identity-core` and `@kashscript/lexicons` only. Like the other published packages, it is Bun-first today: the TypeScript sources are what `main` points at.
