/**
 * A practice desk — a door, in a practice run. It publishes a rule signed with
 * its own key, sends the rule's request with a fresh nonce, checks what comes
 * back with `@kashscript/predicate` (offline, against its own pinned lists),
 * routes it, and hands an automatic decision back as a receipt over the
 * practice handoff. A route to a person gets no automatic receipt: a person
 * decides. **Practice only.** It records only what a real desk would see: a
 * packet arrives; a no never does.
 *
 * A desk either publishes its own rule, or **adopts** another author's with its
 * own values within the rule's bounds (d85(b) rule 8): then it is the anchor —
 * its request carries the adoption, it routes under the adopted values, and
 * the decision is its own standing decision, issued by it (d85(d)).
 */

import { generateKeyPair, deriveDid, type KashKeyPair } from "@kashscript/identity-core";
import type { StatusListReport, TrustListReport } from "@kashscript/attest/holder";
import {
  artifactHolderOf,
  checkPacket,
  criterionQueries,
  KASH_ARTIFACT_FORMAT,
  decisionFromRoute,
  DECISION_VCT,
  issueDecision,
  readAdoption,
  readRule,
  route,
  ruleRequest,
  signAdoption,
  signRule,
  type AdoptionBody,
  type DecisionBody,
  type PacketCheck,
  type ReadAdoption,
  type ReadRule,
  type RouteResult,
  type RuleBody,
  type RuleRequest,
} from "@kashscript/predicate";
import { bytesToHex } from "../../crypto/bytes";
import type { Clock, HttpRequest, HttpResponse } from "../../platform";
import { PracticeIssuer } from "./issuer";
import { formOf, json } from "./network";

const DAY = 86_400;
const rand = (): string => bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
const isoOf = (sec: number): string => new Date(sec * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");

export interface DeskReceived {
  readonly route: RouteResult;
  readonly check: PacketCheck;
  /** Every holder key the packet showed — for the assertion that two desks never see the same one. */
  readonly holderKeys: readonly string[];
}

export class PracticeDesk {
  readonly did: string;
  readonly received: DeskReceived[] = [];
  trustLists: readonly TrustListReport[] = [];
  statusLists: readonly StatusListReport[] = [];
  private rule: ReadRule | null = null;
  private adoption: ReadAdoption | null = null;
  private readonly pending = new Map<string, RuleRequest>();

  private constructor(
    readonly origin: string,
    readonly name: string,
    private readonly key: KashKeyPair,
    private readonly now: Clock,
    private readonly issuer: PracticeIssuer,
  ) {
    this.did = deriveDid(key.publicKey);
  }

  static async create(opts: { origin: string; name: string; now: Clock }): Promise<PracticeDesk> {
    const key = await generateKeyPair();
    const issuer = await PracticeIssuer.create({
      origin: opts.origin,
      name: opts.name,
      now: opts.now,
      key,
      extra: {
        decision: {
          vct: DECISION_VCT,
          issue: async ({ holder, now, context, signer }) => {
            const c = context as { body: DecisionBody; rule: ReadRule; adoption: ReadAdoption | null };
            return issueDecision({ body: c.body, rule: c.rule, ...(c.adoption !== null ? { adoption: c.adoption } : {}), issuer: signer, holderPublicKey: holder, iatUnix: now, expUnix: now + 365 * DAY });
          },
        },
      },
    });
    return new PracticeDesk(opts.origin, opts.name, key, opts.now, issuer);
  }

  private get signer() {
    return { keyid: this.did, privateKey: this.key.privateKey, publicKey: this.key.publicKey };
  }

  /** Publish the door's rule — its author is this desk. */
  async publish(body: RuleBody): Promise<ReadRule> {
    this.rule = await readRule(await signRule(body, this.signer));
    this.adoption = null;
    return this.rule;
  }

  /**
   * Adopt another author's rule with this desk's own values, inside the rule's
   * bounds — signed by this desk as the anchor. Adopted now, reviewed within a
   * year, and ending no later than the rule.
   */
  async adopt(rule: ReadRule, slug: string, parameters: AdoptionBody["parameters"]): Promise<ReadAdoption> {
    const now = this.now();
    const renewBy = Math.min(now + 365 * DAY, Date.parse(rule.body.dates.renewBy) / 1000);
    const body: AdoptionBody = {
      id: `${this.did}/adoption/${slug}`,
      anchor: this.did,
      rule: { id: rule.body.id, version: rule.body.version, hash: rule.hash },
      parameters,
      dates: { adopted: isoOf(now), renewBy: isoOf(renewBy), endsAt: rule.body.dates.endsAt },
      practice: true,
    };
    this.adoption = await readAdoption(await signAdoption(body, rule, this.signer), rule);
    this.rule = rule;
    return this.adoption;
  }

  /** The rule's request, with a fresh nonce and state — from this desk as the anchor when it adopted the rule. */
  request(): RuleRequest {
    if (this.rule === null) throw new Error("publish or adopt a rule first");
    const req = ruleRequest(this.rule, { nonce: rand(), responseUri: `${this.origin}/door`, state: rand(), ...(this.adoption !== null ? { adoption: this.adoption } : {}) });
    this.pending.set(req.state!, req);
    return req;
  }

  /**
   * Every holder key the packet showed: an SD-JWT's `cnf`, and a countersigned
   * record's holder as the query names it — read with predicate's
   * `artifactHolderOf`, the key its binding was checked against (KS-Q11).
   */
  private holderKeysOf(check: PacketCheck, vp: unknown): string[] {
    const rule = this.rule!;
    const token = typeof vp === "object" && vp !== null ? (vp as Record<string, unknown>) : {};
    const out: string[] = [];
    for (const c of rule.body.criteria) {
      const by = check.byCriterion[c.id];
      for (const m of by === undefined ? [] : [...by.receipts, ...by.predicates]) {
        if (m.view.holder !== null) {
          out.push(m.view.holder);
          continue;
        }
        if (m.view.format !== KASH_ARTIFACT_FORMAT) continue;
        const q = criterionQueries(rule.body, rule.hash, c).queries.find((x) => x.id === m.queryId);
        const list = token[m.queryId];
        const item = (Array.isArray(list) ? list : [list])[Number(m.view.ref.split("#")[1] ?? 0)] as { artifact?: Record<string, unknown> } | undefined;
        const holder = q === undefined || item?.artifact === undefined ? null : artifactHolderOf(q, m.view, item.artifact);
        if (holder !== null && !out.includes(holder)) out.push(holder);
      }
    }
    return out;
  }

  readonly handler = async (req: HttpRequest): Promise<HttpResponse> => {
    if (req.method === "POST" && new URL(req.url).pathname === "/door") return this.answer(req);
    return this.issuer.handler(req);
  };

  private async answer(req: HttpRequest): Promise<HttpResponse> {
    const form = formOf(req);
    const pending = this.pending.get(form.get("state") ?? "");
    if (pending === undefined || this.rule === null) return json(400, { error: "invalid_request" });
    this.pending.delete(form.get("state")!);
    let vp: unknown;
    try {
      vp = JSON.parse(form.get("vp_token") ?? "null");
    } catch {
      return json(400, { error: "invalid_request" });
    }
    const now = this.now();
    const check = await checkPacket({ rule: this.rule, request: pending, vp_token: vp, ctx: { trustLists: this.trustLists, statusLists: this.statusLists }, asOf: now });
    const routed = await route(this.rule, check, { asOf: now, ...(this.adoption !== null ? { adoption: this.adoption } : {}) });
    const holderKeys = this.holderKeysOf(check, vp);
    this.received.push({ route: routed, check, holderKeys });
    const out: Record<string, unknown> = { route: routed.route, missing: routed.missing.map((m) => m.criterion), told: routed.told };
    if (routed.route !== "to-a-person") {
      const body = decisionFromRoute(routed, this.rule, { decidedAt: new Date(now * 1000).toISOString() });
      out.decision_offer = this.issuer.offer(["decision"], { body, rule: this.rule, adoption: this.adoption });
    }
    return json(200, out);
  }
}
