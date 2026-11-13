/**
 * A practice issuer that follows the contract a wallet will meet: OID4VCI 1.0
 * pre-authorized issuance (single-use offers, anonymous access, a nonce
 * endpoint, key proofs checked), issuing through attest's own functions.
 * Everything it signs says it is practice (d11), and its names ascribe no
 * identity to anyone.
 */

import { generateKeyPair, deriveDid, signEvent, type KashKeyPair, parseDidKey, type KashPublicKey } from "@kashscript/identity-core";
import type { DsseEnvelope } from "@kashscript/attest/dsse";
import { issuePredicateCredential, issueThankYou, PREDICATE_VCT, THANK_YOU_VCT } from "@kashscript/attest/exchange";
import {
  createStatusBitstring,
  encodeStatusList,
  setStatusBit,
  signStatusList,
  STATUS_LIST_FORMAT,
  type StatusListEntry,
} from "@kashscript/attest/holder";
import { decodeJws, verifyJws } from "@kashscript/attest/sd-jwt";
import { bytesToHex, sha256Hex, utf8 } from "../../crypto/bytes";
import type { Clock, HttpRequest, HttpResponse } from "../../platform";
import { formOf, json, jsonOf } from "./network";

const PRE_AUTH = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
const DAY = 86_400;
export const PRACTICE_RECORD_DST = "kash-record-v1\n";

const rand = (n = 16): string => bytesToHex(crypto.getRandomValues(new Uint8Array(n)));
const iso = (unix: number): string => new Date(unix * 1000).toISOString();

export type PracticeConfig = "practice-visit" | "practice-yes" | "practice-thank-you";

/**
 * A further SD-JWT a practice issuer can hand over — a door's receipts and its
 * decisions in the door tests. Issued in copies, one per key the wallet proves,
 * the same content in each; `context` is what the offer was minted with.
 */
export interface PracticeSdJwtConfig {
  readonly vct: string;
  readonly issue: (args: {
    readonly holder: KashPublicKey;
    readonly now: number;
    readonly context: unknown;
    readonly signer: { readonly keyid: string; readonly did: string; readonly privateKey: Uint8Array; readonly publicKey: Uint8Array };
  }) => Promise<string>;
}

export class PracticeIssuer {
  readonly did: string;
  readonly statusUrl: string;
  /** Every key a wallet proved it held — for the assertion that none of them is shared. */
  readonly seenKeys: string[] = [];
  private readonly bits = createStatusBitstring();
  private readonly used = new Set<number>();
  private readonly codes = new Map<string, { configs: string[]; used: boolean; context: unknown }>();
  private readonly tokens = new Map<string, { configs: string[]; context: unknown }>();
  private readonly nonces = new Set<string>();

  private constructor(
    readonly origin: string,
    readonly name: string,
    private readonly key: KashKeyPair,
    private readonly now: Clock,
    readonly batchSize: number,
    /** Declared at the handoff as `kash_retention_until`, when set. */
    readonly retentionSec: number | null,
    private readonly extra: Readonly<Record<string, PracticeSdJwtConfig>>,
  ) {
    this.did = deriveDid(key.publicKey);
    this.statusUrl = `${origin}/status/1`;
  }

  static async create(opts: {
    origin: string;
    name: string;
    now: Clock;
    batchSize?: number;
    retentionSec?: number;
    /** Issue as this key — a desk issues its decisions as the organisation whose rule it applies. */
    key?: KashKeyPair;
    extra?: Readonly<Record<string, PracticeSdJwtConfig>>;
  }): Promise<PracticeIssuer> {
    return new PracticeIssuer(opts.origin, opts.name, opts.key ?? (await generateKeyPair()), opts.now, opts.batchSize ?? 5, opts.retentionSec ?? null, opts.extra ?? {});
  }

  private signer() {
    return { keyid: this.did, did: this.did, privateKey: this.key.privateKey, publicKey: this.key.publicKey };
  }

  /** A single-use offer, as the deep link a QR code would carry. */
  offer(configs: readonly (PracticeConfig | string)[], context: unknown = null): string {
    const code = rand();
    this.codes.set(code, { configs: [...configs], used: false, context });
    const offer = { credential_issuer: this.origin, credential_configuration_ids: configs, grants: { [PRE_AUTH]: { "pre-authorized_code": code } } };
    return `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;
  }

  /** A random index — never issue order — in a list of 131,072 entries. */
  private statusEntry(): StatusListEntry {
    let i: number;
    do i = crypto.getRandomValues(new Uint32Array(1))[0]! % 131_072;
    while (this.used.has(i));
    this.used.add(i);
    return { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: String(i), statusListCredential: this.statusUrl };
  }

  revoke(entry: StatusListEntry): void {
    setStatusBit(this.bits, Number(entry.statusListIndex), true);
  }

  async statusList(): Promise<DsseEnvelope> {
    return signStatusList(
      { format: STATUS_LIST_FORMAT, type: "BitstringStatusList", id: this.statusUrl, issuer: this.did, statusPurpose: "revocation", encodedList: await encodeStatusList(this.bits), issuedAtUnix: this.now(), validUntilUnix: null },
      this.signer(),
    );
  }

  readonly handler = async (req: HttpRequest): Promise<HttpResponse> => {
    const path = new URL(req.url).pathname;
    if (req.method === "GET" && path === "/.well-known/openid-credential-issuer") {
      return json(200, {
        credential_issuer: this.origin,
        credential_endpoint: `${this.origin}/credential`,
        nonce_endpoint: `${this.origin}/nonce`,
        batch_credential_issuance: { batch_size: this.batchSize },
        credential_configurations_supported: {
          "practice-visit": { format: "kash-artifact", dst: PRACTICE_RECORD_DST },
          "practice-yes": { format: "dc+sd-jwt", vct: PREDICATE_VCT },
          "practice-thank-you": { format: "dc+sd-jwt", vct: THANK_YOU_VCT },
          ...Object.fromEntries(Object.entries(this.extra).map(([id, c]) => [id, { format: "dc+sd-jwt", vct: c.vct }])),
        },
      });
    }
    if (req.method === "GET" && path === "/.well-known/oauth-authorization-server") {
      return json(200, { issuer: this.origin, token_endpoint: `${this.origin}/token`, "pre-authorized_grant_anonymous_access_supported": true });
    }
    if (req.method === "POST" && path === "/token") {
      const form = formOf(req);
      const grant = this.codes.get(form.get("pre-authorized_code") ?? "");
      if (form.get("grant_type") !== PRE_AUTH || grant === undefined || grant.used || form.has("client_id")) return json(400, { error: "invalid_grant" });
      grant.used = true;
      const token = rand();
      this.tokens.set(token, { configs: grant.configs, context: grant.context });
      return json(200, { access_token: token, token_type: "Bearer", expires_in: 300 });
    }
    if (req.method === "POST" && path === "/nonce") {
      const nonce = rand();
      this.nonces.add(nonce);
      return json(200, { c_nonce: nonce });
    }
    if (req.method === "POST" && path === "/credential") return this.credential(req);
    if (req.method === "GET" && path === "/status/1") return json(200, await this.statusList());
    return json(404, { error: "not_found" });
  };

  private async credential(req: HttpRequest): Promise<HttpResponse> {
    const grant = this.tokens.get((req.headers.authorization ?? "").replace(/^Bearer /, ""));
    const body = jsonOf(req);
    const config = body?.credential_configuration_id as string | undefined;
    if (grant === undefined || config === undefined || !grant.configs.includes(config)) return json(401, { error: "invalid_token" });
    const proofs = (body?.proofs as { jwt?: unknown } | undefined)?.jwt;
    const max = config === "practice-yes" || this.extra[config] !== undefined ? this.batchSize : 1;
    if (!Array.isArray(proofs) || proofs.length === 0 || proofs.length > max) return json(400, { error: "invalid_proof" });

    const holders: KashPublicKey[] = [];
    for (const p of proofs) {
      const jws = typeof p === "string" ? decodeJws(p) : null;
      const kid = jws?.header.kid;
      // The proof key's type — Ed25519 or P-256 from a phone's secure chip — comes from its did:kash.
      let pub: KashPublicKey | null = null;
      try {
        pub = typeof kid === "string" ? parseDidKey(kid) : null;
      } catch {
        pub = null;
      }
      const nonce = jws?.payload.nonce;
      const fresh = typeof jws?.payload.iat === "number" && Math.abs(jws.payload.iat - this.now()) <= 300;
      if (jws === null || pub === null || jws.header.typ !== "openid4vci-proof+jwt" || jws.payload.aud !== this.origin || typeof nonce !== "string" || !this.nonces.has(nonce) || !fresh || !(await verifyJws(jws, pub))) {
        return json(400, { error: "invalid_proof" });
      }
      this.seenKeys.push(kid as string);
      holders.push(pub);
    }
    for (const p of proofs) this.nonces.delete(decodeJws(p as string)!.payload.nonce as string);

    const now = this.now();
    const credentials: { credential: unknown }[] = [];
    const extra = this.extra[config];
    for (const holder of holders) {
      credentials.push({ credential: extra !== undefined ? await extra.issue({ holder, now, context: grant.context, signer: this.signer() }) : await this.issue(config as PracticeConfig, holder, now) });
    }
    return json(200, { credentials, ...(this.retentionSec !== null ? { kash_retention_until: now + this.retentionSec } : {}) });
  }

  private async issue(config: PracticeConfig, holder: KashPublicKey, now: number): Promise<unknown> {
    if (config === "practice-visit") {
      const header = { iss: this.did, typ: "practice-visit" };
      const body = { practice: true, what: "a practice visit record — not a real-world fact", atUnix: now, expiresAtUnix: now + 180 * DAY };
      const signature = await signEvent(header, body, this.key.privateKey, { kid: this.did });
      return { header, body, signature };
    }
    if (config === "practice-yes") {
      return issuePredicateCredential({
        issuer: this.signer(),
        holderPublicKey: holder,
        predicate: {
          kind: "practice-rule-followed",
          answer: true,
          rule: { id: "practice-rule-1", version: "1", hash: await sha256Hex(utf8("practice rule 1")) },
          window: { from: iso(now - 30 * DAY), to: iso(now - DAY) },
        },
        restsOn: [await sha256Hex(utf8(`practice record ${rand()}`))],
        credentialStatus: this.statusEntry(),
        iatUnix: now,
        expUnix: now + 365 * DAY,
      });
    }
    return issueThankYou({
      issuer: this.signer(),
      holderPublicKey: holder,
      for: { act: "confirmed-session", session: "practice-session" },
      value: "Practice: a free cup of tea on your next visit",
      redeemAt: `the counter of ${this.name}`,
      iatUnix: now,
      expUnix: now + 90 * DAY,
      credentialStatus: this.statusEntry(),
    });
  }
}
