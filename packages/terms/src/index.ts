/**
 * @kashscript/terms — agreements with a declared split.
 *
 * A deterministic state machine, a dust-free declared split, a sealed manifest,
 * a signed completion receipt and a subscription thread. It moves nothing and
 * holds no balance: money moves on the payer's own rails, and Duedale confirms
 * that it arrived. Its states describe the agreement, never a person.
 */

export * from "./errors";
export * from "./types";
export * from "./splitter";
export * from "./fsm";
export * from "./manifest";
export * from "./completion-receipt";
export * from "./subscription-thread";
