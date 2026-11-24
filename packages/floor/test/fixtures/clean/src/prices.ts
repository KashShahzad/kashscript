/** The price file, in Indorania's shape: a price per accepted outcome by entrance, the allowance, plans and packs. */

export interface Amount {
  readonly usd: number | null;
  readonly pkr: number | null;
}

export interface PriceFile {
  readonly asOf: string | null;
  readonly yes: { readonly link: Amount; readonly api: Amount };
  readonly allowance: { readonly link: number | null; readonly api: number | null };
  readonly plans: { readonly pro: Amount; readonly team: Amount };
  readonly packs: readonly { readonly name: string; readonly price: Amount }[];
}

export const PRICES: PriceFile = {
  asOf: "2026-11-15",
  yes: { link: { usd: 1, pkr: 100 }, api: { usd: 0.1, pkr: 10 } },
  allowance: { link: 5, api: 100 },
  plans: { pro: { usd: 49, pkr: 5000 }, team: { usd: 199, pkr: 20000 } },
  packs: [{ name: "small", price: { usd: 20, pkr: 2000 } }],
};
