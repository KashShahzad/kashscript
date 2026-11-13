/**
 * The thank-you voucher (ECOSYSTEM d49(b); specs/thank-you.md).
 *
 * A promise, not a balance: an SD-JWT VC signed by the counterparty that gives
 * it — never by Indorania or a member — naming the holder's relationship key in
 * `cnf`, what it is for (the answering, never the answer), a value **as text**,
 * where it is redeemed, an expiry and a redemption status index.
 *
 *   • **No balance, amount, count or transfer field** — nothing can sum
 *     thank-yous into a balance or a score. The verifier refuses any.
 *   • **Non-transferable:** redeeming is presenting it to its own issuer with a
 *     KB-JWT from the holder key; whoever else holds the string cannot.
 *   • The redemption index is the issuer's status list: a set bit reads
 *     *used or withdrawn*.
 */

import { issueSdJwt, verifySdJwt, type SdJwtReport } from "../sd-jwt/sd-jwt";
import { jwkOf, type JwsSigner } from "../sd-jwt/jws";
import type { VerifyKey } from "../signing";
import type { KeyResolver } from "../holder/keys";
import { checkStatus, statusEntryOf, type StatusListEntry, type StatusListReport, type StatusVerdict } from "../holder/status-list";
import { THANK_YOU_VCT } from "./constants";


/** What a thank-you is for: the act of answering — never what the answer was (d49 rule 1). */
export type ThankYouFor =
  | { readonly act: "answered-ask"; readonly ask: string }
  | { readonly act: "confirmed-session"; readonly session: string };

/** Field names a voucher may never carry, at any depth: they would let something sum it. */
export const FORBIDDEN_VOUCHER_FIELDS: readonly string[] = [
  "amount", "balance", "total", "sum", "points", "score", "count", "credits", "currency",
  "rank", "tier", "level", "transfer", "transferable", "bearer",
];
/** Field names that would carry the answer — a thank-you rewards answering, never the answer (d49 rule 1). */
export const ANSWER_FIELDS: readonly string[] = ["answer", "outcome", "result", "verdict", "confirmed", "disputed"];

export interface IssueThankYouInput {
  /** The counterparty giving it — an establishment, or a verifier running asks. */
  readonly issuer: JwsSigner & { readonly did: string };
  /** A bare 32-byte key is Ed25519; a typed key may be P-256. */
  readonly holderPublicKey: VerifyKey;
  readonly for: ThankYouFor;
  /** In plain words — "a free coffee on your next visit". Never a number to add up. */
  readonly value: string;
  /** Where it is redeemed, in plain words or a URL of the issuer's own. */
  readonly redeemAt: string;
  readonly iatUnix: number;
  readonly expUnix: number;
  readonly credentialStatus: StatusListEntry | null;
}

export async function issueThankYou(input: IssueThankYouInput): Promise<string> {
  if (typeof input.value !== "string" || input.value.trim().length === 0) throw new Error("a thank-you's value is text");
  return issueSdJwt({
    header: { kid: input.issuer.did },
    claims: {
      iss: input.issuer.did,
      iat: input.iatUnix - (input.iatUnix % 86_400),
      exp: input.expUnix,
      vct: THANK_YOU_VCT,
      cnf: { jwk: jwkOf(input.holderPublicKey) },
      ...(input.credentialStatus !== null ? { credentialStatus: input.credentialStatus } : {}),
      for: input.for,
      value: input.value,
      redeemAt: input.redeemAt,
    },
    signer: input.issuer,
  });
}

export type ThankYouFailureReason =
  | "SD_JWT_INVALID"
  | "NOT_A_THANK_YOU"
  | "VOUCHER_MALFORMED"
  | "BALANCE_FIELD"
  | "ANSWER_CARRIED"
  | "NOT_HOLDER_BOUND"
  | "REDEEMED_ELSEWHERE"
  | "USED_OR_WITHDRAWN";

export interface ThankYouReport {
  readonly ok: boolean;
  readonly reason: ThankYouFailureReason | null;
  readonly sdJwt: SdJwtReport;
  readonly issuer: string | null;
  /** The relationship identifier the voucher is bound to. */
  readonly holder: string | null;
  readonly for: ThankYouFor | null;
  readonly value: string | null;
  readonly redeemAt: string | null;
  readonly expiresAtUnix: number | null;
  readonly status: StatusVerdict;
  readonly notes: readonly string[];
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function fieldNamed(names: readonly string[], v: unknown, path: string): string | null {
  if (Array.isArray(v)) {
    for (let i = 0; i < v.length; i++) {
      const hit = fieldNamed(names, v[i], `${path}[${i}]`);
      if (hit !== null) return hit;
    }
    return null;
  }
  if (!isPlainObject(v)) return null;
  for (const [k, val] of Object.entries(v)) {
    if (names.includes(k.toLowerCase())) return `${path}.${k}`;
    const hit = fieldNamed(names, val, `${path}.${k}`);
    if (hit !== null) return hit;
  }
  return null;
}

/** A voucher's status, in its own words: a set bit means used or withdrawn. */
function voucherStatus(v: StatusVerdict): StatusVerdict {
  if (v.state === "not-revoked") return { ...v, text: v.text.replace("valid unless revoked", "not yet used, unless withdrawn since") };
  if (v.state === "revoked") return { ...v, text: v.text.replace(/^revoked/, "used or withdrawn") };
  return v;
}

async function check(input: string, opts: VerifyThankYouOptions, requireKeyBinding: boolean): Promise<ThankYouReport> {
  const sd = await verifySdJwt(input, {
    resolveKey: opts.resolveKey,
    requireKeyBinding,
    ...(opts.nowSec !== undefined ? { nowSec: opts.nowSec } : {}),
    ...(opts.nonce !== undefined ? { nonce: opts.nonce } : {}),
    ...(opts.maxKbAgeSec !== undefined ? { maxKbAgeSec: opts.maxKbAgeSec } : {}),
  });
  const c = sd.claims;
  const status = voucherStatus(checkStatus(statusEntryOf(c), opts.statusLists ?? []));
  const f = c !== null && isPlainObject(c.for) ? (c.for as unknown as ThankYouFor) : null;
  let reason: ThankYouFailureReason | null = null;
  if (!sd.ok) reason = "SD_JWT_INVALID";
  else if (sd.vct !== THANK_YOU_VCT) reason = "NOT_A_THANK_YOU";
  else if (fieldNamed(ANSWER_FIELDS, c, "$") !== null) reason = "ANSWER_CARRIED";
  else if (fieldNamed(FORBIDDEN_VOUCHER_FIELDS, c, "$") !== null) reason = "BALANCE_FIELD";
  else if (
    f === null ||
    !((f.act === "answered-ask" && typeof (f as { ask?: unknown }).ask === "string") || (f.act === "confirmed-session" && typeof (f as { session?: unknown }).session === "string")) ||
    Object.keys(f).length !== 2
  ) {
    reason = "ANSWER_CARRIED";
  } else if (typeof c?.value !== "string" || typeof c.redeemAt !== "string") reason = "VOUCHER_MALFORMED";
  else if (sd.holder === null) reason = "NOT_HOLDER_BOUND";
  return {
    ok: reason === null,
    reason,
    sdJwt: sd,
    issuer: sd.issuer,
    holder: sd.holder,
    for: f,
    value: typeof c?.value === "string" ? c.value : null,
    redeemAt: typeof c?.redeemAt === "string" ? c.redeemAt : null,
    expiresAtUnix: typeof c?.exp === "number" ? c.exp : null,
    status,
    notes: [...sd.notes, "a promise, not a balance: nothing here adds up"],
  };
}

export interface VerifyThankYouOptions {
  readonly resolveKey: KeyResolver;
  readonly nowSec?: number;
  readonly statusLists?: readonly StatusListReport[];
  readonly nonce?: string;
  readonly maxKbAgeSec?: number;
}

/** Verify a held thank-you: its issuer, its shape, and that nothing in it can be summed. */
export function verifyThankYou(voucher: string, opts: VerifyThankYouOptions): Promise<ThankYouReport> {
  return check(voucher, opts, false);
}

/**
 * Verify a redemption: the voucher presented by its holder, to its own issuer.
 * Fails if it is bound to another audience, if anyone but the holder's key
 * signed it, or if the issuer's status list says it is used or withdrawn.
 */
export async function verifyRedemption(presentation: string, opts: VerifyThankYouOptions): Promise<ThankYouReport> {
  const r = await check(presentation, opts, true);
  if (!r.ok) return r;
  if (r.sdJwt.keyBinding.audience !== r.issuer) return { ...r, ok: false, reason: "REDEEMED_ELSEWHERE" };
  if (r.status.state === "revoked") return { ...r, ok: false, reason: "USED_OR_WITHDRAWN" };
  return r;
}
