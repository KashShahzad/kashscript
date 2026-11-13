/**
 * Blueprint registry — one Blueprint per ProductId.
 */

import type { Blueprint, ProductId } from "./types";
import { IDENTITY_BLUEPRINT } from "./identity";
import { TERMS_BLUEPRINT }    from "./terms";
import { MUFFLER_BLUEPRINT }  from "./muffler";
import { WHIFFIN_BLUEPRINT }  from "./whiffin";

export * from "./types";
export { IDENTITY_BLUEPRINT, TERMS_BLUEPRINT, MUFFLER_BLUEPRINT, WHIFFIN_BLUEPRINT };

export const BLUEPRINTS: Readonly<Record<ProductId, Blueprint>> = {
  identity: IDENTITY_BLUEPRINT,
  terms:    TERMS_BLUEPRINT,
  muffler:  MUFFLER_BLUEPRINT,
  whiffin:  WHIFFIN_BLUEPRINT,
};

export function getBlueprint(id: ProductId): Blueprint {
  return BLUEPRINTS[id];
}

/** Every product `kash add` can install, in the order the help lists them. */
export const PRODUCT_IDS: readonly ProductId[] = ["identity", "terms", "muffler", "whiffin"];

export function isProductId(s: string): s is ProductId {
  return (PRODUCT_IDS as readonly string[]).includes(s);
}

/**
 * Products that used to be `kash add` targets and are gone (ecosystem d59, d87, d90), with where to
 * go instead. `kash add` answers these by name rather than calling them unknown.
 *
 * hudhud left on 2026-11-02 (KS-P1, ADR-0024): it is Indorania's closed runtime inside the Oreoasis
 * engine, never published again, so an open CLI must not scaffold an import of it.
 */
export const RETIRED_PRODUCTS: Readonly<Record<string, string>> = {
  trade:
    "trade-core and trade-sdk are retired. The agreement kernel is now @kashscript/terms; run `kash add terms`.",
  neuron:
    "neuron is Indorania's closed code inside the Oreoasis engine (ecosystem d87, d90; since 2026-11-02) and is not installed by kash. For an accountable AI helper, use Oreoasis's API.",
  hudhud:
    "hudhud is Indorania's closed runtime inside the Oreoasis engine (ecosystem d87, d90; since 2026-11-02) and is not installed by kash. The open kit is identity, terms, muffler and whiffin; for an accountable AI helper, use Oreoasis's API.",
};
