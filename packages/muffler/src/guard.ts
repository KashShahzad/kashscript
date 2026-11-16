// @kashscript/muffler/guard — the guard ECOSYSTEM d59 asks for: muffler publishes public, organisation-
// authored records, never a person's (KS-N1, folding in KS-R5).
//
// Two halves. By KIND: only the kernel's public record lexicons are admitted (`PUBLIC_RECORD_LEXICONS` —
// the door's rule and adoption, places, listings, guides, the two lists); any other collection under the
// protocol's namespace — a person's profile, a social post, a decision receipt — is REFUSED with a report,
// never skipped in silence. By CONTENT: a record that has its shape is read for a person's identity — an
// email, a phone number, a DID in words — and refused when it carries one (`findPersonIdentity`), after the
// cross-field rules its kind has (`publicRecordFaults`).
//
// What the guard cannot do, said plainly: tell a person's key from an organisation's. No directory of people
// exists, by design (d41); the indexer learns a repository's DID and the record's `publisher`, and neither
// says what kind of party holds the key. A key is an organisation's when a trust list says so (d91(f)), and
// that reading is KS-Q4's. Nothing here verifies a signature either: the lists are the clear payloads attest
// signs, and attest verifies them.

import { LexiconRegistry, compareSemver, type LexiconDef } from "@kashscript/lexicons";
import { PUBLIC_RECORD_LEXICONS, findPersonIdentity, publicRecordFaults } from "@kashscript/lexicons/extensions/public";
import { RefineError, createLexiconRefiner, type RefinedRecord, type Refiner } from "./refine";

export interface PublicRecordGuardOptions {
  /** The public record lexicons to admit. Default: every public, organisation-authored lexicon the kernel knows. */
  readonly lexicons?: readonly LexiconDef[];
  /** The namespaces the guard answers for: a collection under one of them is handled, and refused unless admitted. Default `["kash"]`. */
  readonly namespaces?: readonly string[];
}

/** The newest registered version of each NSID: a record in collection `kash.rule` validates as `kash.rule@1.2.0`, since every older body is a 1.2.0 body. */
function newestByNsid(lexicons: readonly LexiconDef[]): Map<string, LexiconDef> {
  const newest = new Map<string, LexiconDef>();
  for (const d of lexicons) {
    const prev = newest.get(d.nsid);
    if (prev === undefined || compareSemver(d.semver, prev.semver) > 0) newest.set(d.nsid, d);
  }
  return newest;
}

/**
 * A `Refiner` for the public records. It handles every collection under its namespaces and every admitted
 * NSID; it refuses a collection it does not admit (`PERSON_RECORD`), a body without its shape
 * (`INVALID_RECORD`), one that breaks a cross-field rule (`INVALID_ATTRIBUTES`, with the faults) and one that
 * carries a person's identity (`PERSON_IDENTITY`, with the finding). The indexer reports each and goes on.
 */
export function createPublicRecordGuard(opts: PublicRecordGuardOptions = {}): Refiner {
  const lexicons = opts.lexicons ?? PUBLIC_RECORD_LEXICONS;
  const namespaces = opts.namespaces ?? ["kash"];
  const newest = newestByNsid(lexicons);
  const registry = new LexiconRegistry().registerAll(lexicons);
  const owned = (collection: string): boolean => namespaces.some((ns) => collection === ns || collection.startsWith(`${ns}.`));

  const inner = createLexiconRefiner({
    registry,
    collectionToLexiconId: (collection) => newest.get(collection)?.id ?? null,
    postValidate: (collection, value) => {
      const faults = publicRecordFaults(collection, value);
      if (faults.length > 0) {
        throw new RefineError("INVALID_ATTRIBUTES", `${collection}: ${faults.map((f) => f.code).join(", ")}`, faults);
      }
      const hit = findPersonIdentity(value);
      if (hit !== null) {
        throw new RefineError(
          "PERSON_IDENTITY",
          `${collection} carries ${hit.what} at ${hit.path.join(".")} — a public record names organisations and places, never a person (d59)`,
          hit,
        );
      }
    },
  });

  return {
    handles(collection: string): boolean {
      return owned(collection) || newest.has(collection);
    },
    async refine(collection: string, record: unknown): Promise<RefinedRecord> {
      if (!newest.has(collection)) {
        throw new RefineError(
          "PERSON_RECORD",
          `${collection} is not a public, organisation-authored record kind; muffler publishes no person's record (d59)`,
          { collection, admitted: [...newest.keys()] },
        );
      }
      return inner.refine(collection, record);
    },
  };
}

/**
 * One refiner from several: the first that handles a collection refines it. A host indexes the public
 * records and its own `app.*` records through one indexer — the guard beside the venture's refiner.
 */
export function composeRefiners(...refiners: readonly Refiner[]): Refiner {
  return {
    handles(collection: string): boolean {
      return refiners.some((r) => r.handles(collection));
    },
    refine(collection: string, record: unknown): Promise<RefinedRecord> {
      const chosen = refiners.find((r) => r.handles(collection));
      if (chosen === undefined) return Promise.reject(new RefineError("UNKNOWN_COLLECTION", `Unknown collection: ${collection}`));
      return chosen.refine(collection, record);
    },
  };
}
