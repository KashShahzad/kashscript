/**
 * `@kashscript/attest/batch` — accepting a batch on a sample (PY-5; `specs/attestation/batch.md`).
 *
 * One root over many items (`./items`) · the seal fixed before the draw (`./seal`) · the draw, from a Bitcoin
 * block named in the seal and mined after its OpenTimestamps stamp (`./beacon`, `./draw`) · the exact
 * arithmetic of the bound and the plan (`./chance`) · the checks a stranger runs (`./verify`) · the words a
 * person reads (`./words`). The record is `kash.attestation@1.1.0`'s `batch` (`../attestation`).
 */

export * from "./chance";
export * from "./draw";
export * from "./items";
export * from "./seal";
export * from "./beacon";
export * from "./verify";
export * from "./words";
