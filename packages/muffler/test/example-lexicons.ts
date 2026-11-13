// Example lexicons for the muffler test suite. These stand in for the venture's
// app.indusland.* lexicons (which stay venture-side, ADR-0016 guard b) so the
// generic package proves the indexer/refiner behaviors without importing across
// repos (ECOSYSTEM: copy patterns, never import). Two collections mirror the
// seed's profile + experience: an experience REQUIRES a non-empty subcategories
// array, so a record missing it fails validation — reproducing the seed's
// "invalid record is skipped, not fatal" path.

import { LexiconRegistry, S } from "@kashscript/lexicons";
import { createLexiconRefiner } from "../src/refine";
import type { Refiner } from "../src/refine";

export const EXAMPLE = {
  profile: "com.example.profile",
  experience: "com.example.experience",
} as const;

const LEXICON_ID: Record<string, string> = {
  [EXAMPLE.profile]: "com.example.profile@1.0.0",
  [EXAMPLE.experience]: "com.example.experience@1.0.0",
};

export function collectionToLexiconId(collection: string): string | null {
  return LEXICON_ID[collection] ?? null;
}

export function exampleRegistry(): LexiconRegistry {
  const registry = new LexiconRegistry();
  registry.register(
    "com.example.profile@1.0.0",
    S.object({ displayName: S.string({ minLength: 1 }) }, ["displayName"]),
  );
  registry.register(
    "com.example.experience@1.0.0",
    S.object(
      {
        title: S.string({ minLength: 1 }),
        subcategories: S.array(S.string(), { minItems: 1 }),
      },
      ["title", "subcategories"],
    ),
  );
  return registry;
}

export function exampleRefiner(): Refiner {
  return createLexiconRefiner({ registry: exampleRegistry(), collectionToLexiconId });
}
