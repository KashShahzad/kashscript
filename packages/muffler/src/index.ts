// @kashscript/muffler — the Data Protocol (PDS + firehose).
//
// A transport-agnostic, did:kash-bound atproto-style PDS client + firehose
// indexer with CID content-addressing, an injectable Refiner (lexicon
// validation via @kashscript/lexicons), and pluggable record sinks. Built in
// phase M3 of the protocol Manifestation (ADR-0016); the generic machinery is
// derived from the @indus/muffler venture seed, and the venture-specific
// lexicons / refine rules / rm_* projections / Supabase schema stay
// venture-side (guard b). Apache-2.0 — portable hosting is free.
//
// The Supabase sink is NOT re-exported here: it lives behind the
// `@kashscript/muffler/sink-supabase` subpath so importing this barrel never
// pulls in the `@supabase/supabase-js` peer dependency.

export * from "./cid";
export * from "./refine";
export * from "./identity";
export * from "./client";
export * from "./indexer";
export { MemoryRecordSink } from "./sinks/memory";

/** Bumped whenever a wire-level behaviour (CID form, refine contract, firehose
 *  message shape, binding record) changes. */
export const MUFFLER_VERSION = "0.1.0" as const;
