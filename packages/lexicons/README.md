# @kashscript/lexicons

> **Zero-dependency lexicon framework — envelope, schema DSL, registry, validator.** Domain-agnostic core; vocabularies ship as opt-in extensions.

```bash
bun add @kashscript/lexicons
```

A *lexicon* is the Kash equivalent of an AT-Protocol record schema: a
versioned, NSID-addressed JSON shape that describes what valid `kash.*`
records look like. This package gives you the primitives to **define**,
**register**, and **validate** lexicons — but ships zero domain content
out of the box. The open protocol's public records (`door`, `place`, `lists`,
listed together in `public`) and the apps' vocabularies (`social`, `zkp`,
`education`, `civic`, `community`) are explicit subpath imports.

---

## What's in the box

| Subpath                                | Purpose                                              |
|----------------------------------------|------------------------------------------------------|
| `@kashscript/lexicons`                 | Default — the framework + identity-tier `STANDARD_LIBRARY` |
| `@kashscript/lexicons/envelope`        | Kash-Event envelope shape (header + body + signature) + `RecordRef` |
| `@kashscript/lexicons/schema`          | Schema DSL — the `S` builder (`S.object`, `S.string`, …) + `validate()` |
| `@kashscript/lexicons/registry`        | `LexiconRegistry` — register, lookup, version-resolve |
| `@kashscript/lexicons/engine`          | `validateEvent` / `validateBody` / `getSchemaDefinition` |
| `@kashscript/lexicons/json-schema`     | Export lexicons as JSON Schema (draft 2020-12)       |
| `@kashscript/lexicons/semver`          | Strict semver for lexicon evolution                  |
| `@kashscript/lexicons/extensions/social` | The `kash.social.*` vocabulary                     |
| `@kashscript/lexicons/extensions/zkp`    | The `kash.zkp.*` vocabulary                        |
| `@kashscript/lexicons/extensions/{education,civic,community}` | Further opt-in vocabularies |
| `@kashscript/lexicons/extensions/door` | `kash.rule@1.0.0` and `kash.rule@1.1.0` (a door's published rule; 1.1.0 adds its address, drafts, parameter bounds and each criterion's subject) and `kash.adoption@1.0.0` (an anchor adopts a rule with local values within its bounds). All three are public, organisation-authored records (d59). The decision receipt is the person's record, so its shape lives in `@kashscript/predicate` since `0.3.0-alpha.0`. Meaning is checked by `@kashscript/predicate`; see `specs/rule.md`, `specs/adoption.md` and `specs/decision.md` |
| `@kashscript/lexicons/extensions/place` | `kash.place@1.0.0` (a place by its publisher's DID and a slug — no coordinate, d60), `kash.place.pointer@1.0.0` (a place's new publisher), `kash.listing@1.0.0` (an offering with its published price — no rating) and `kash.guide@1.0.0` (a text about places). Public, organisation-authored records (d59), with the cross-field checks the shape cannot write (`placeFaults`, …). See `specs/public-records.md` |
| `@kashscript/lexicons/extensions/lists` | `kash.trust-list@1.0.0` — attest's `kashscript-trust-list/1` payload in clear, with d91's three assertions (identity · standing · scope) and issuer classes — and `kash.status-list@1.0.0`, attest's `kashscript-status-list/1`. The record's CID is the hash of the bytes attest signs |
| `@kashscript/lexicons/extensions/public` | `PUBLIC_RECORD_LEXICONS` — every public record kind in one list (the door's, the places', the lists'), `publicRecordFaults`, and `findPersonIdentity`, the scan muffler's guard runs: an email, a phone number or a DID in words is refused |

---

## Quickstart

```typescript
import { S } from "@kashscript/lexicons/schema";
import { LexiconRegistry } from "@kashscript/lexicons/registry";
import { validateBody, validateEvent } from "@kashscript/lexicons/engine";

// 1. Define a body schema with the `S` builder (3rd arg of S.object = required keys).
const noteSchema = S.object(
  {
    text:      S.string({ maxLength: 280 }),
    createdAt: S.string({ format: "iso8601" }),
  },
  ["text", "createdAt"],
);

// 2. Register it under `<nsid>@<semver>` (register() is chainable).
const registry = new LexiconRegistry();
registry.register("com.example.note@1.0.0", noteSchema, { title: "Example Note" });

// 3a. Validate a record body before signing it.
const bodyResult = validateBody(
  "com.example.note@1.0.0",
  { text: "hello world", createdAt: new Date().toISOString() },
  registry,
);
if (!bodyResult.ok) console.error(bodyResult.errors); // [{ path, message, received }]

// 3b. Or validate a full signed Kash-Event envelope (header.lexicon picks the schema).
const eventResult = validateEvent(incomingEvent, registry); // incomingEvent: unknown
if (eventResult.ok) console.log("valid:", eventResult.value.header.lexicon);
```

---

## License

Apache-2.0. See [LICENSE](./LICENSE).
