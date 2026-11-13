# Lexicon Versioning & Migration

How `@kashscript/lexicons` schemas evolve once they're in the wild.

## The namespace

Every Kash lexicon ships under a fully-qualified id:

```
kash.<domain>.<noun>@<major>.<minor>.<patch>
```

Examples:

```
kash.social.post@1.0.0
kash.education.transcript@1.0.0
kash.civic.permit@1.0.0
```

The major.minor.patch is **semver** with stricter semantics than the npm
norm:

| Bump | When | Example |
|---|---|---|
| **patch** | Documentation / metadata only. Wire shape unchanged. | `1.0.0 → 1.0.1` — added a `description` to one optional field. |
| **minor** | Strictly additive: new optional field, new optional enum case. Old consumers continue to parse new records. | `1.0.0 → 1.1.0` — added optional `tags` to `kash.social.post`. |
| **major** | Wire-breaking. A required field changed type, was removed, or a field was renamed. Old consumers reject new records. | `1.x → 2.0.0` — `kash.social.post.text` becomes required (was optional). |

The version is **part of the id** — `kash.social.post@1.0.0` and
`kash.social.post@2.0.0` are different lexicons. Records carry the
fully-qualified id in their envelope header; the validator dispatches
on it.

## Side-by-side hosting

A registry can hold multiple versions of the same lexicon at the same
time:

```ts
import { LexiconRegistry } from "@kashscript/lexicons/registry";
import { SOCIAL_EXTENSION as SOCIAL_V1 } from "@kashscript/lexicons/extensions/social";
// hypothetical v2 (when it ships):
// import { SOCIAL_EXTENSION as SOCIAL_V2 } from "@kashscript/lexicons/extensions/social-v2";

const registry = new LexiconRegistry();
registry.registerAll(SOCIAL_V1);
// registry.registerAll(SOCIAL_V2);

// Records carry the version they were authored against; the registry
// dispatches via the @ tag.
const v1Record = { header: { lexicon: "kash.social.post@1.0.0", ... }, ... };
const v2Record = { header: { lexicon: "kash.social.post@2.0.0", ... }, ... };
```

Hosts that want to accept both should register both extensions. A host
that wants to FORCE migration registers only the new version; records
authored against the old one fail validation.

## Migration pattern

The recommended progression when shipping a new major:

1. **Author the new schema** at the next major version. Keep the old
   schema imported in the same file so it remains exportable.

2. **Ship a migrator** — a pure function `(oldBody) → newBody` that
   covers the wire-breaking change. Conventional name:
   `migrate_kash_social_post_v1_to_v2(body)`.

3. **Dual-register for a window** — hosts accept both `@1.x` and `@2.x`
   for at least one quarter, OR until logged read-volume against `@1.x`
   drops below a threshold (e.g., 1% of total).

4. **Server-side rewrite** — hosts that own the storage can run the
   migrator over historical records and re-emit them under `@2.x` (this
   requires the original signer to re-sign; see "Signatures don't migrate"
   below).

5. **Drop the old version** — registry stops accepting `@1.x`; any client
   still writing it gets a `LEXICON_UNKNOWN` error.

## Signatures don't migrate

A record's signature covers the CANONICAL bytes of `{ header, body }`.
A migrator changes the bytes by definition, so the migrated body's old
signature no longer verifies. Two options:

- **Re-sign at migration time** — only the original signer can do this,
  via their identity-core Signer. Many hosts can't get to the signer
  (it's on the user's device).
- **Republish under a new signature** — issue the migrated record with
  a new signer (e.g., the host acting as a "migration proxy"). The
  audit trail loses the original signer's attestation; appropriate for
  display-layer migrations but not for compliance-sensitive records.

A migrated record SHOULD carry a `meta.migratedFrom` field pointing at
the original record's cid so verifiers can trace back if needed.

## Compatibility shim pattern

When you can't break old consumers but want to add a required field,
add it as **optional with a default**, then bump major in a later
release to make it required:

```ts
// kash.community.membership@1.1.0
// added optional `role` — old consumers ignore it
export const KASH_COMMUNITY_MEMBERSHIP_BODY_SCHEMA_V11 = S.object({
  ...
  role: S.optional(S.string({ minLength: 1, maxLength: 64 })),
}, [...]);

// kash.community.membership@2.0.0 (later)
// `role` is now required — minor bump first gave consumers six months
// to add it
export const KASH_COMMUNITY_MEMBERSHIP_BODY_SCHEMA_V20 = S.object({
  ...
  role: S.string({ minLength: 1, maxLength: 64 }), // no longer optional
}, [..., "role"]);
```

## What we ship today

As of 2026-05-28 every shipped extension is at `1.0.0` with no migration
debt:

```
kash.social.post@1.0.0           kash.social.interaction@1.0.0
kash.social.follow@1.0.0         kash.education.transcript@1.0.0
kash.education.peer-review@1.0.0 kash.civic.permit@1.0.0
kash.civic.petition@1.0.0        kash.community.membership@1.0.0
kash.community.aid-claim@1.0.0   kash.trade.*@1.0.0
kash.zkp.*@1.0.0
```

When the first migrator ships, it goes under
`packages/lexicons/src/migrators/<lexicon-name>.ts` with the convention
above and a one-line addition to this doc.
