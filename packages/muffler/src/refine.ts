// refine — the record-refinement seam: validate a record against its lexicon,
// canonicalize it (RFC 8785 / JCS via identity-core), and content-address it
// (CIDv1). Pure and isomorphic; no I/O.
//
// The seed (@indus/muffler) hardwired a Zod `refine()` over its app.indusland
// schemas. Here the *rules* are INJECTED via the `Refiner` interface so the
// package stays venture-neutral: a venture supplies its own refiner (wrapping
// its Zod schemas), and `createLexiconRefiner` is the reference implementation
// backed by `@kashscript/lexicons` (ROADMAP M3 item 4). The indexer + client
// consume a `Refiner`; they never import a concrete schema.

import { canonicalizeBytes } from "@kashscript/identity-core";
import { validateBody } from "@kashscript/lexicons";
import type { LexiconRegistry } from "@kashscript/lexicons";
import { cidForBytes } from "./cid";

export type RefineErrorCode =
  | "UNKNOWN_COLLECTION"
  | "INVALID_RECORD"
  | "INVALID_ATTRIBUTES";

/** A record that failed refinement. The indexer treats a `RefineError` as a
 *  skip-with-report (non-fatal); anything else aborts the message. */
export class RefineError extends Error {
  constructor(
    readonly code: RefineErrorCode,
    message: string,
    readonly detail?: unknown,
  ) {
    super(message);
    this.name = "RefineError";
  }
}

/** A validated, canonicalized, content-addressed record. */
export interface RefinedRecord {
  collection: string;
  /** The validated record body (as returned by the refiner's validator). */
  value: unknown;
  /** The RFC 8785 (JCS) canonical form of `value`. */
  canonical: string;
  /** CIDv1 (raw codec, sha2-256) over the canonical bytes. */
  cid: string;
}

/**
 * The refinement seam. A venture implements this from its own lexicon rules;
 * the indexer + client depend only on this interface.
 *
 * - `handles(collection)` — whether this refiner knows the collection (the
 *   indexer skips ops for collections it does not handle).
 * - `refine(collection, record)` — validate + canonicalize + content-address,
 *   or throw `RefineError` on an invalid record / unknown collection.
 */
export interface Refiner {
  handles(collection: string): boolean;
  refine(collection: string, record: unknown): Promise<RefinedRecord>;
}

export interface LexiconRefinerOptions {
  /** The registry the record bodies validate against. */
  readonly registry: LexiconRegistry;
  /** Maps a collection NSID to a full lexicon id (`nsid@semver`), or null if
   *  the collection is not handled by this refiner. */
  readonly collectionToLexiconId: (collection: string) => string | null;
  /** Optional post-validation hook (generalizes the seed's per-subcategory
   *  attribute validator). Throw `RefineError` to reject the record. */
  readonly postValidate?: (collection: string, value: unknown) => void;
}

/**
 * The reference `Refiner`, backed by `@kashscript/lexicons`. Validates a record
 * body against its registered lexicon, runs an optional post-validation hook,
 * then canonicalizes (JCS) and content-addresses (CIDv1).
 */
const DANGEROUS_KEYS = new Set(["__proto__", "constructor", "prototype"]);

/** Deep-clone a validated record, dropping prototype-polluting own-keys. Returns
 *  a fresh structure (never the input by reference). audit r1 F5. */
function sanitizeRecord(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sanitizeRecord);
  if (v !== null && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v)) {
      if (DANGEROUS_KEYS.has(k)) continue;
      out[k] = sanitizeRecord(val);
    }
    return out;
  }
  return v;
}

export function createLexiconRefiner(opts: LexiconRefinerOptions): Refiner {
  const { registry, collectionToLexiconId, postValidate } = opts;
  return {
    handles(collection: string): boolean {
      return collectionToLexiconId(collection) !== null;
    },
    async refine(collection: string, record: unknown): Promise<RefinedRecord> {
      const lexiconId = collectionToLexiconId(collection);
      if (lexiconId === null) {
        throw new RefineError("UNKNOWN_COLLECTION", `Unknown collection: ${collection}`);
      }
      const result = validateBody(lexiconId, record, registry);
      if (!result.ok) {
        throw new RefineError("INVALID_RECORD", "Record failed lexicon validation", result.errors);
      }
      // audit r1 F5: the validator returns the untrusted input BY REFERENCE, and
      // lexicon validation does not strip prototype-polluting keys. Deep-clone and
      // drop `__proto__`/`constructor`/`prototype` own-keys before the record
      // reaches venture sinks / canonicalization — pollution can't ride through.
      const value = sanitizeRecord(result.value) as typeof result.value;
      if (postValidate) postValidate(collection, value);

      const bytes = canonicalizeBytes(value);
      const canonical = new TextDecoder().decode(bytes as unknown as BufferSource);
      const cid = await cidForBytes(bytes);
      return { collection, value, canonical, cid };
    },
  };
}
