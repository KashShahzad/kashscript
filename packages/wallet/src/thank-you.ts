/**
 * Thank-yous (d49(b); thank-you spec). A thank-you is a promise, never a
 * balance: each one is shown as a single note — what it is, who gave it, until
 * when — and nothing here adds them up. There is no total, count, sum or
 * balance anywhere in this API (d49: no points, tiers, balances or
 * leaderboards; d51: never summed into a balance).
 *
 * Claiming one is receiving it (the handoff, with keeping records switched on
 * for that place). Using one is presenting it to whoever gave it, and only
 * them — it is bound to the holder's key with that place, so it cannot move.
 */

import { credentialCopySha256, THANK_YOU_VCT, verifyThankYou } from "@kashscript/attest/exchange";
import { presentSdJwt } from "@kashscript/attest/sd-jwt";
import { fill } from "./copy";
import type { WalletCore } from "./core";
import { WalletError } from "./errors";

export interface ThankYouNote {
  readonly id: string;
  /** In the giver's plain words — text, never a number to add up. */
  readonly value: string;
  readonly from: string;
  readonly redeemAt: string;
  readonly untilUnix: number | null;
  /** Whether it has been used, in the issuer's own list's words, naming its time. */
  readonly status: string;
  /** One sentence a surface can show as the note. */
  readonly words: string;
}

export interface RedeemRequest {
  /** The issuer — a thank-you is used only with whoever gave it. */
  readonly client_id: string;
  readonly nonce: string;
  /** Where to send it. Absent: the presentation is returned to show at the counter. */
  readonly response_uri?: string;
  readonly state?: string;
}

export class ThankYous {
  constructor(private readonly core: WalletCore) {}

  /** Every thank-you held, each on its own. */
  async list(): Promise<readonly ThankYouNote[]> {
    const out: ThankYouNote[] = [];
    const resolveKey = await this.core.trust.resolver();
    const statusLists = await this.core.trust.statusReports();
    for (const e of await this.core.records.list()) {
      if (e.manifest.type.tag !== THANK_YOU_VCT || typeof e.artifact.value !== "string") continue;
      const r = await verifyThankYou(e.artifact.value, { resolveKey, statusLists, nowSec: this.core.now() });
      if (!r.ok || r.value === null || r.issuer === null) continue;
      const place = e.local.counterparty === null ? null : await this.core.relationships.find(e.local.counterparty);
      const from = place?.label ?? e.local.counterparty ?? r.issuer;
      out.push({
        id: e.slot,
        value: r.value,
        from,
        redeemAt: r.redeemAt ?? "",
        untilUnix: r.expiresAtUnix,
        status: r.status.text,
        words: fill(this.core.copy.thankYouNote, { value: r.value, name: from }),
      });
    }
    return out;
  }

  /**
   * Use a thank-you with its giver. Refused before anything is made if the
   * request is from anyone else. Returns the presentation; sends it too when
   * the request names where.
   */
  async redeem(id: string, request: RedeemRequest): Promise<string> {
    const e = await this.core.records.get(id);
    if (e === null || e.manifest.type.tag !== THANK_YOU_VCT || typeof e.artifact.value !== "string" || e.local.boundKey === null) throw new WalletError("NOT_FOUND");
    if (request.client_id !== e.manifest.issuer) throw new WalletError("REDEEM_ELSEWHERE");
    const voucher = e.artifact.value;
    const presentation = await this.core.keys.withSigner(e.local.boundKey, (s) =>
      presentSdJwt(voucher, () => false, s, { aud: request.client_id, nonce: request.nonce, iatUnix: this.core.now() }),
    );
    if (request.response_uri !== undefined) {
      const res = await this.core.postForm(
        request.response_uri,
        { vp_token: JSON.stringify({ "thank-you": [presentation] }), ...(request.state !== undefined ? { state: request.state } : {}) },
        await this.core.allowed([e.local.boundKey]),
      );
      if (res.status < 200 || res.status >= 300) throw new WalletError("SEND_FAILED", `the giver answered ${res.status}`);
    }
    await this.core.log.append({
      kind: "presentation",
      atUnix: this.core.now(),
      verifier: request.client_id,
      relationship: e.local.boundKey,
      ask: null,
      credentials: [{ vct: THANK_YOU_VCT, copySha256: await credentialCopySha256(voucher) }],
      disclosed: [],
      attachedRecordIds: [],
      linkedByHolder: false,
    });
    return presentation;
  }
}
