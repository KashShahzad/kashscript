/**
 * Trade Extension — domain lexicons (Duedale-shaped but Duedale-agnostic).
 *
 *   kash.trade.offer@1.0.0    — an item / service for sale.
 *   kash.trade.receipt@1.0.0  — a cryptographically signed completed transaction.
 *   kash.trade.status@1.0.0   — a lightweight logistics update.
 *
 * Import path: `@kashscript/lexicons/extensions/trade`.
 *
 * This file is an **extension**: the Foundry core never auto-loads it.
 * Consumers explicitly register `TRADE_EXTENSION` against their
 * `LexiconRegistry` to opt in to trade-domain validation.
 *
 * Prices follow ISO 4217 (currency codes) and store amounts as DECIMAL STRINGS
 * to avoid IEEE-754 float drift. Locations use ISO 3166-2 region codes when
 * available, falling back to free-form region strings.
 */

import { RECORD_REF_SCHEMA, type RecordRef } from "../envelope";
import type { LexiconDef } from "../registry";
import { S, type ObjectSchema } from "../schema";

/* ─────────────────────────────────────────────────────────────────
 * Money — ISO 4217 amount as a decimal string. AI-parseable.
 * ───────────────────────────────────────────────────────────────── */

const DECIMAL_AMOUNT_RE = /^(?:0|[1-9][0-9]{0,17})(?:\.[0-9]{1,8})?$/;

export type PriceUnit = "fixed" | "per-hour" | "per-day" | "per-month" | "per-unit";

export interface PriceSpec {
  readonly amount: string;
  readonly currency: string;
  readonly unit?: PriceUnit;
}

const PRICE_SPEC: ObjectSchema = S.object(
  {
    amount:   S.string({ pattern: DECIMAL_AMOUNT_RE, maxLength: 32 }),
    currency: S.string({ format: "iso4217" }),
    unit:     S.optional(S.enum("fixed", "per-hour", "per-day", "per-month", "per-unit")),
  },
  ["amount", "currency"],
);

/* ─────────────────────────────────────────────────────────────────
 *  kash.trade.offer@1.0.0
 * ───────────────────────────────────────────────────────────────── */

export const KASH_TRADE_OFFER_NSID    = "kash.trade.offer" as const;
export const KASH_TRADE_OFFER_VERSION = { major: 1, minor: 0, patch: 0 } as const;
export const KASH_TRADE_OFFER_ID      = "kash.trade.offer@1.0.0" as const;

export type TradeCategory  = "goods" | "services" | "rentals" | "digital";
export type TradeStatus    = "open" | "reserved" | "closed";
export type FulfilmentMode = "pickup" | "ship" | "digital";

export interface OfferMediaRef {
  readonly cid: string;
  readonly mimeType: "image/jpeg" | "image/png" | "image/webp";
}

export interface LocationSpec {
  readonly region: string;
  readonly handler: FulfilmentMode;
}

export interface KashTradeOfferBody {
  readonly title: string;
  readonly description?: string;
  readonly category: TradeCategory;
  readonly price: PriceSpec;
  readonly media?: readonly OfferMediaRef[];
  readonly location?: LocationSpec;
  readonly validUntil?: string;
  readonly status: TradeStatus;
  readonly relatedPost?: RecordRef;
}

const OFFER_MEDIA_REF: ObjectSchema = S.object(
  {
    cid:      S.string({ format: "cid" }),
    mimeType: S.enum("image/jpeg", "image/png", "image/webp"),
  },
  ["cid", "mimeType"],
);

const LOCATION_SPEC: ObjectSchema = S.object(
  {
    region:  S.string({ minLength: 1, maxLength: 64 }),
    handler: S.enum("pickup", "ship", "digital"),
  },
  ["region", "handler"],
);

export const KASH_TRADE_OFFER_BODY_SCHEMA: ObjectSchema = S.object(
  {
    title:       S.string({ minLength: 1, maxLength: 140 }),
    description: S.optional(S.string({ maxLength: 4000 })),
    category:    S.enum("goods", "services", "rentals", "digital"),
    price:       PRICE_SPEC,
    media:       S.optional(S.array(OFFER_MEDIA_REF, { maxItems: 8 })),
    location:    S.optional(LOCATION_SPEC),
    validUntil:  S.optional(S.string({ format: "iso8601" })),
    status:      S.enum("open", "reserved", "closed"),
    relatedPost: S.optional(RECORD_REF_SCHEMA),
  },
  ["title", "category", "price", "status"],
);

/* ─────────────────────────────────────────────────────────────────
 *  kash.trade.receipt@1.0.0
 *
 *  Dual-receipt pattern: each party publishes their OWN receipt.
 *  Cross-domain interop: optional `linkedPost` references a `kash.social.post`.
 * ───────────────────────────────────────────────────────────────── */

export const KASH_TRADE_RECEIPT_NSID    = "kash.trade.receipt" as const;
export const KASH_TRADE_RECEIPT_VERSION = { major: 1, minor: 0, patch: 0 } as const;
export const KASH_TRADE_RECEIPT_ID      = "kash.trade.receipt@1.0.0" as const;

export type TradeRole = "buyer" | "seller";

export interface KashTradeReceiptBody {
  readonly offer: RecordRef;
  readonly counterparty: string;
  readonly role: TradeRole;
  readonly price: PriceSpec;
  readonly settledAt: string;
  readonly paymentRef?: string;
  readonly counterpartyReceipt?: RecordRef;
  readonly linkedPost?: RecordRef;
}

export const KASH_TRADE_RECEIPT_BODY_SCHEMA: ObjectSchema = S.object(
  {
    offer:               RECORD_REF_SCHEMA,
    counterparty:        S.string({ format: "did-ks" }),
    role:                S.enum("buyer", "seller"),
    price:               PRICE_SPEC,
    settledAt:           S.string({ format: "iso8601" }),
    paymentRef:          S.optional(S.string({ minLength: 1, maxLength: 128 })),
    counterpartyReceipt: S.optional(RECORD_REF_SCHEMA),
    linkedPost:          S.optional(RECORD_REF_SCHEMA),
  },
  ["offer", "counterparty", "role", "price", "settledAt"],
);

/* ─────────────────────────────────────────────────────────────────
 *  kash.trade.status@1.0.0
 * ───────────────────────────────────────────────────────────────── */

export const KASH_TRADE_STATUS_NSID    = "kash.trade.status" as const;
export const KASH_TRADE_STATUS_VERSION = { major: 1, minor: 0, patch: 0 } as const;
export const KASH_TRADE_STATUS_ID      = "kash.trade.status@1.0.0" as const;

export type TradeState =
  | "pending" | "shipped" | "in-transit" | "delivered"
  | "received" | "disputed" | "refunded" | "cancelled";

export interface KashTradeStatusBody {
  readonly receipt: RecordRef;
  readonly state: TradeState;
  readonly note?: string;
  readonly trackingRef?: string;
  readonly at?: string;
}

export const KASH_TRADE_STATUS_BODY_SCHEMA: ObjectSchema = S.object(
  {
    receipt:     RECORD_REF_SCHEMA,
    state:       S.enum("pending", "shipped", "in-transit", "delivered", "received", "disputed", "refunded", "cancelled"),
    note:        S.optional(S.string({ minLength: 1, maxLength: 280 })),
    trackingRef: S.optional(S.string({ minLength: 1, maxLength: 128 })),
    at:          S.optional(S.string({ format: "iso8601" })),
  },
  ["receipt", "state"],
);

/* ─────────────────────────────────────────────────────────────────
 *  Extension bundle
 * ───────────────────────────────────────────────────────────────── */

/** All Trade-domain lexicons. Pass to `LexiconRegistry.registerAll()`. */
export const TRADE_EXTENSION: readonly LexiconDef[] = [
  {
    id: KASH_TRADE_OFFER_ID,
    nsid: KASH_TRADE_OFFER_NSID,
    semver: KASH_TRADE_OFFER_VERSION,
    bodySchema: KASH_TRADE_OFFER_BODY_SCHEMA,
    title: "Trade Offer",
    description: "An item or service for sale — ISO 4217 price, optional location and media.",
  },
  {
    id: KASH_TRADE_RECEIPT_ID,
    nsid: KASH_TRADE_RECEIPT_NSID,
    semver: KASH_TRADE_RECEIPT_VERSION,
    bodySchema: KASH_TRADE_RECEIPT_BODY_SCHEMA,
    title: "Trade Receipt",
    description: "Cryptographically signed completed transaction. Dual-receipt pattern; optionally links to a social post.",
  },
  {
    id: KASH_TRADE_STATUS_ID,
    nsid: KASH_TRADE_STATUS_NSID,
    semver: KASH_TRADE_STATUS_VERSION,
    bodySchema: KASH_TRADE_STATUS_BODY_SCHEMA,
    title: "Trade Status",
    description: "Lightweight logistics update bound to a receipt.",
  },
];
