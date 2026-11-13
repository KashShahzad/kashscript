/**
 * Muffler blueprint — `kash add muffler`.
 *
 * Scaffolds a typed PDS-client + firehose-sink config so an app can wire the
 * KashScript data protocol (portable `did:kash`-bound Personal Data Store +
 * firehose indexer) with a memory sink today and swap in the Supabase sink
 * (the `./sink-supabase` subpath, `@supabase/supabase-js` peer) for production.
 */

import type { Blueprint } from "./types";

export const MUFFLER_BLUEPRINT: Blueprint = {
  id: "muffler",
  title: "Kash Muffler",
  description: "Portable did:kash-bound PDS client + firehose indexer + pluggable sinks.",
  blueprintVersion: "0.1.0",

  operations: [
    {
      kind: "install-dep",
      description: "Install the muffler data protocol.",
      spec: { name: "@kashscript/muffler", version: "^0.1.0" },
    },
    {
      kind: "write-file",
      description: "Scaffold lib/muffler-client.ts.",
      path: "lib/muffler-client.ts",
      managed: false,
      content: () => `/**
 * lib/muffler-client.ts — scaffolded by \`kash add muffler\`.
 *
 * The KashScript data protocol: a portable, \`did:kash\`-bound Personal Data
 * Store (repo/record CRUD, CID content-addressing) plus a firehose indexer
 * that projects records into a Sink. Start on the in-memory sink; move to the
 * Supabase sink (\`@kashscript/muffler/sink-supabase\`, needs the
 * \`@supabase/supabase-js\` peer) when you need durable, queryable projections.
 */

// import { ... PDS client / firehose ... } from "@kashscript/muffler";
// import { createSupabaseSink } from "@kashscript/muffler/sink-supabase";

export interface MufflerConfig {
  /** Your PDS host base URL. */
  readonly pdsUrl: string;
  /** The repo owner's DID. Every write is bound to this identity. */
  readonly ownerDid: \`did:kash:\${string}\`;
  /** Where the firehose indexer projects records. Start in-memory. */
  readonly sink?: "memory" | "supabase";
}

/**
 * Wire the muffler PDS client + firehose to your app. The generic protocol
 * ships lexicon validation as an INJECTED Refiner — pass your app's lexicon
 * validators (via @kashscript/lexicons) so venture-specific record shapes stay
 * on your side, never in the protocol.
 */
export function createMufflerClient(_config: MufflerConfig): never {
  throw new Error(
    "Wire lib/muffler-client.ts to @kashscript/muffler: construct the PDS client + " +
    "firehose indexer with your injected Refiner and chosen sink. See specs/muffler.md.",
  );
}
`,
    },
    {
      kind: "patch-turbo-json",
      description: "Register kash:doctor as a turbo task (monorepo-turbo only).",
      path: "tasks.kash:doctor",
      strategy: "set-if-missing",
      value: { cache: false, persistent: false },
      requires: { paradigm: ["monorepo-turbo"] },
    },
  ],

  verifications: [
    { kind: "dep-present", description: "muffler dependency present.", name: "@kashscript/muffler" },
    { kind: "file-exists", description: "lib/muffler-client.ts exists.", path: "lib/muffler-client.ts" },
  ],
};
