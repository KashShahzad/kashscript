/**
 * A practice verifier: publishes an ask, sends it as an OpenID4VP request, and
 * checks what comes back with attest — offline, against the ask, its own
 * identifier and the nonce it sent. It records only what a real verifier
 * would see: a yes arrives; a no never does.
 */

import { generateKeyPair, deriveDid } from "@kashscript/identity-core";
import { ASK_FORMAT, askRequest, verifyPredicatePresentation, type Ask, type PredicatePresentationReport } from "@kashscript/attest/exchange";
import { makeKeyResolver, type StatusListReport } from "@kashscript/attest/holder";
import { bytesToHex } from "../../crypto/bytes";
import type { Clock, HttpRequest, HttpResponse } from "../../platform";
import { formOf, json } from "./network";

const DAY = 86_400;
const rand = (): string => bytesToHex(crypto.getRandomValues(new Uint8Array(12)));

export interface Received {
  readonly needId: string;
  readonly presentation: string;
  readonly report: PredicatePresentationReport;
}

export class PracticeVerifier {
  readonly did: string;
  /** Every presentation that arrived, as checked. A decline adds nothing here — there is nothing to arrive. */
  readonly received: Received[] = [];
  /** The lists this verifier checks status against — the issuer's, as it would fetch them. */
  statusLists: readonly StatusListReport[] = [];
  private readonly pending = new Map<string, { ask: Ask; nonce: string }>();

  private constructor(
    readonly origin: string,
    readonly name: string,
    did: string,
    private readonly now: Clock,
  ) {
    this.did = did;
  }

  static async create(opts: { origin: string; name: string; now: Clock }): Promise<PracticeVerifier> {
    return new PracticeVerifier(opts.origin, opts.name, deriveDid((await generateKeyPair()).publicKey), opts.now);
  }

  /** A published ask, in plain words, for the practice predicate. */
  ask(key: string, overrides: Partial<Pick<Ask, "title" | "why" | "goodFor">> = {}): Ask {
    const now = this.now();
    return {
      format: ASK_FORMAT,
      key,
      version: 1,
      title: overrides.title ?? "Show the practice rule was followed",
      who: { name: this.name, id: this.did },
      needs: [{ id: "n1", predicate: "practice-rule-followed", withinDays: 90 }],
      why: overrides.why ?? "A practice check: we only accept work done under the rule in force at the time.",
      answer: { form: "yes", restsOn: "issuers" },
      goodFor: overrides.goodFor ?? "The practice job is accepted without a second visit.",
      declining: "costs-only-goodFor",
      linking: "separate",
      published: { library: "https://asks.practice.invalid/library", atUnix: now - DAY },
      expiresAtUnix: now + 60 * DAY,
      state: "published",
    };
  }

  /** The OpenID4VP request an ask becomes, with a fresh nonce and a state to match the answer. */
  async request(ask: Ask): Promise<Record<string, unknown>> {
    const nonce = rand();
    const state = rand();
    this.pending.set(state, { ask, nonce });
    return { ...(await askRequest(ask, { nonce, responseUri: `${this.origin}/response` })), state };
  }

  readonly handler = async (req: HttpRequest): Promise<HttpResponse> => {
    if (req.method !== "POST" || new URL(req.url).pathname !== "/response") return json(404, { error: "not_found" });
    const form = formOf(req);
    const pending = this.pending.get(form.get("state") ?? "");
    let vpToken: unknown;
    try {
      vpToken = JSON.parse(form.get("vp_token") ?? "");
    } catch {
      return json(400, { error: "invalid_request" });
    }
    if (pending === undefined || typeof vpToken !== "object" || vpToken === null) return json(400, { error: "invalid_request" });
    this.pending.delete(form.get("state") ?? "");
    for (const need of pending.ask.needs) {
      const list = (vpToken as Record<string, unknown>)[need.id];
      if (!Array.isArray(list) || typeof list[0] !== "string") return json(400, { error: "invalid_request" });
      const report = await verifyPredicatePresentation(list[0], {
        resolveKey: makeKeyResolver(new Map(), new Map()),
        audience: this.did,
        nonce: pending.nonce,
        ask: pending.ask,
        needId: need.id,
        statusLists: this.statusLists,
        nowSec: this.now(),
      });
      this.received.push({ needId: need.id, presentation: list[0], report });
    }
    return json(200, {});
  };
}
