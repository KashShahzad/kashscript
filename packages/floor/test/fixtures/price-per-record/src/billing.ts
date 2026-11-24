export const CHECK_FEE_USD = 0.25;

export interface Fees {
  readonly perRequest: number;
  readonly monthly: string;
}

/** A rate limit, not a price: per request, but nothing here is money. */
export const LIMITS = { maxPerRequest: 50 };
