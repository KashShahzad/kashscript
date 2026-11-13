/**
 * @kashscript/predicate — the rule engine for doors (ECOSYSTEM d59, d84).
 *
 *   rule      → a door's published rule (`kash.rule@1.2.0`; 1.1.0 and 1.0.0 still read):
 *               validated against the floor, hashed, signed by its author,
 *               sent as a request — with its address (ISIC Rev 5, the anchor
 *               family, the authority, the journey, the seven givens) and the
 *               bounds of its parameters (d85(b), (c));
 *   adoption  → an anchor adopts a rule with local values within its bounds
 *               (`kash.adoption@1.0.0`), signed as itself (d85(b) rule 8);
 *   checklist → the rule checked on the person's side first, against the
 *               receipts they hold — a row per criterion, never a score;
 *   packet    → what the person sends by choice: a copy per viewer, bound to
 *               that viewer's nonce and audience; and the desk's free check;
 *   route     → automatic-yes, not-yet or to-a-person — never a refusal;
 *   decision  → the decision receipt (`kash.decision@1.1.0`, its shape kept
 *               here — a person's record, not a public one, d59), signed by the
 *               deciding organisation to the person, who keeps it.
 *
 * Pure and deterministic: no clock (every function takes `asOf`), no network
 * (status lists are passed in), no model. A criterion is an OpenID4VP 1.0 DCQL
 * query plus a FEEL condition (a DMN subset — `./feel`). No format of our own
 * (d71): SD-JWT VC, DSSE, DCQL and FEEL, with two extensions in the spec's own
 * extension points, named in `./dcql`. Apache-2.0.
 */

export * from "./constants";
export * from "./vocabulary";
export * from "./isic";
export * from "./address";
export * from "./bounds";
export * from "./receipts";
export * from "./dcql";
export * from "./criteria";
export * from "./rule";
export * from "./adoption";
export * from "./checklist";
export * from "./packet";
export * from "./route";
export * from "./decision";

export const PREDICATE_VERSION = "0.2.0-alpha.0" as const;
