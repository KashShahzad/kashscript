// @kashscript/whiffin/rails — the NAMES of payment rails, and nothing else.
//
// A mandate is declared, the payer pays on their own rail, and the recipient
// confirms arrival: DECLARE → PAY → CONFIRM. Whiffin does not touch the middle
// step. A declaration may CITE a rail by name; nothing dispatches on it, no
// adapter sits behind it, and this module makes no call — it is a closed list of
// strings (the 0.1.0 adapters for these rails were removed in 0.2.0, d59).
//
// The names are wire: a declaration that cites one carries it inside signed
// bytes. Add a name if a payer's rail is missing; never rename or remove one.

/** Rails a declaration can cite. Chain is one optional rail, never a requirement. */
export const RAIL = {
  /** The State Bank of Pakistan's Raast instant-payment rail. */
  RAAST: "RAAST",
  /** An EMVCo merchant-presented QR, paid from the payer's own bank or wallet app. */
  EMVCO: "EMVCO",
  /** The Safepay gateway. */
  SAFEPAY: "SAFEPAY",
  /** A card tap on a SoftPOS terminal. */
  SOFTPOS: "SOFTPOS",
  /** An on-chain transfer — optional, never a requirement. */
  CHAIN: "CHAIN",
} as const;

export type Rail = (typeof RAIL)[keyof typeof RAIL];

/** Every rail name, in declaration order. */
export const RAILS: readonly Rail[] = Object.values(RAIL);

/** True iff `x` is a rail name a declaration may cite. */
export function isRail(x: unknown): x is Rail {
  return typeof x === "string" && (RAILS as readonly string[]).includes(x);
}
