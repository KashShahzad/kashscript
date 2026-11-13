/**
 * Receive — the handoff (holder contract §1). OpenID for Verifiable Credential
 * Issuance 1.0, pre-authorized code flow; nothing invented where it speaks.
 *
 *   offer (QR, deep link, https link or file)
 *     → the switch: is keeping records with this place on?   (unset: ask; off: send nothing)
 *     → issuer metadata, token (anonymous — no client id), nonce
 *     → credential request, each key proof signed by a key made for this place alone
 *     → verify every record with attest, write its manifest, keep it
 *
 * - The wallet identifies itself only by a relationship key (d41, d47(g)): one
 *   key for this place, or — for an SD-JWT it may show others (a yes, a receipt
 *   a door reads, a decision) — a fresh copy key per copy (presentation §4,
 *   d62(d)3). A thank-you stays bound to its place: it is a promise to that
 *   relationship, never shown elsewhere (d49). Never a global id, never a
 *   wallet-instance id.
 * - Every endpoint must be on the issuer's own origin, so no third party learns
 *   a key. A `credential_offer_uri` elsewhere is refused unopened.
 * - A record from an issuer no pinned list names waits in memory for the
 *   holder's choice; discarding it leaves nothing behind.
 * - Offers are single-use: a replay is refused by the issuer, and nothing is stored.
 */

import { THANK_YOU_VCT, verifyThankYou } from "@kashscript/attest/exchange";
import { decodeJws, didOfJwk, parseSdJwt, signJws } from "@kashscript/attest/sd-jwt";
import type { HeldArtifact, HeldRecord } from "@kashscript/attest/holder";
import { bytesToHex } from "./crypto/bytes";
import type { WalletCore } from "./core";
import { WalletError } from "./errors";
import { detectKind, type RecordLocal } from "./records";
import { counterpartyOf, type ProofChoice } from "./relationships";

const PRE_AUTH = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
const PROOF_TYP = "openid4vci-proof+jwt";

export interface CredentialOffer {
  readonly credential_issuer: string;
  readonly credential_configuration_ids: readonly string[];
  readonly grants: Readonly<Record<string, unknown>>;
}

export interface OfferView {
  /** Null only for an offer by reference not yet opened, because the switch isn't on. */
  readonly offer: CredentialOffer | null;
  readonly offerUri: string | null;
  /** The place, named by its own origin. */
  readonly counterparty: string;
  readonly proof: ProofChoice;
  readonly needsTxCode: boolean;
}

/** Records waiting, in memory only, for the holder to choose about an unlisted sender. */
export interface PendingRecords {
  readonly counterparty: string;
  readonly unlistedIssuers: readonly string[];
  readonly items: readonly { readonly record: HeldRecord; readonly local: RecordLocal; readonly needsKeep: boolean }[];
  readonly copyKeys: readonly string[];
}

export type ReceiveResult =
  | { readonly status: "stored"; readonly slots: readonly string[] }
  | { readonly status: "needs-choice"; readonly counterparty: string }
  | { readonly status: "off" }
  | { readonly status: "needs-keep-choice"; readonly pending: PendingRecords };

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function httpsOrigin(url: unknown): string | null {
  if (typeof url !== "string") return null;
  try {
    const u = new URL(url);
    return u.protocol === "https:" ? u.origin : null;
  } catch {
    return null;
  }
}

function asOffer(v: unknown): CredentialOffer {
  if (
    !isPlainObject(v) ||
    httpsOrigin(v.credential_issuer) === null ||
    !Array.isArray(v.credential_configuration_ids) ||
    v.credential_configuration_ids.length === 0 ||
    !v.credential_configuration_ids.every((c) => typeof c === "string") ||
    !isPlainObject(v.grants) ||
    !isPlainObject(v.grants[PRE_AUTH]) ||
    typeof (v.grants[PRE_AUTH] as Record<string, unknown>)["pre-authorized_code"] !== "string"
  ) {
    throw new WalletError("OFFER_INVALID", "not a pre-authorized OID4VCI credential offer");
  }
  return v as unknown as CredentialOffer;
}

function parseInput(input: string | Readonly<Record<string, unknown>>): { offer: CredentialOffer | null; offerUri: string | null } {
  if (typeof input !== "string") return { offer: asOffer(input), offerUri: null };
  const text = input.trim();
  if (text.startsWith("{")) {
    try {
      return { offer: asOffer(JSON.parse(text)), offerUri: null };
    } catch (e) {
      if (e instanceof WalletError) throw e;
      throw new WalletError("OFFER_INVALID", "the offer is not JSON");
    }
  }
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    throw new WalletError("OFFER_INVALID", "not a link");
  }
  const byValue = url.searchParams.get("credential_offer");
  const byRef = url.searchParams.get("credential_offer_uri");
  if (byValue !== null && byRef === null) {
    try {
      return { offer: asOffer(JSON.parse(byValue)), offerUri: null };
    } catch (e) {
      if (e instanceof WalletError) throw e;
      throw new WalletError("OFFER_INVALID", "credential_offer is not JSON");
    }
  }
  if (byRef !== null && byValue === null && httpsOrigin(byRef) !== null) return { offer: null, offerUri: byRef };
  throw new WalletError("OFFER_INVALID", "exactly one of credential_offer or credential_offer_uri (https) is needed");
}

export class Receive {
  constructor(private readonly core: WalletCore) {}

  /**
   * Read an offer. Sends nothing unless the offer is by reference AND keeping
   * records with that place is already on — then it fetches the offer from the
   * place's own host, and only from there.
   */
  async open(input: string | Readonly<Record<string, unknown>>): Promise<OfferView> {
    let { offer, offerUri } = parseInput(input);
    const counterparty = counterpartyOf(offer?.credential_issuer ?? (offerUri as string));
    const proof = await this.core.relationships.proof(counterparty);
    if (offer === null && proof === "on") {
      const res = await this.core.getJson(offerUri as string);
      if (res.status !== 200) throw new WalletError("OFFER_INVALID", `the offer link answered ${res.status}`);
      offer = asOffer(res.json);
      if (counterpartyOf(offer.credential_issuer) !== counterparty) throw new WalletError("OFFER_ORIGIN");
    }
    const grant = offer === null ? null : (offer.grants[PRE_AUTH] as Record<string, unknown>);
    return { offer, offerUri, counterparty, proof, needsTxCode: grant !== null && grant.tx_code !== undefined };
  }

  /** Redeem an opened offer. Gated by the switch; a no, or no answer yet, sends nothing. */
  async accept(view: OfferView, opts: { readonly txCode?: string; readonly keepUnlisted?: boolean } = {}): Promise<ReceiveResult> {
    const proof = await this.core.relationships.proof(view.counterparty);
    if (proof === "unset") return { status: "needs-choice", counterparty: view.counterparty };
    if (proof === "off") return { status: "off" };
    if (view.offer === null) throw new WalletError("OFFER_INVALID", "open the offer again now that records are on");
    const offer = view.offer;
    const issuer = offer.credential_issuer;
    const origin = counterpartyOf(issuer);
    const sameOrigin = (url: unknown): string => {
      if (httpsOrigin(url) !== origin) throw new WalletError("OFFER_ORIGIN", `endpoint ${String(url)} is not on ${origin}`);
      return url as string;
    };

    const md = await this.core.getJson(new URL(`/.well-known/openid-credential-issuer${new URL(issuer).pathname.replace(/^\/$/, "")}`, issuer).href);
    if (md.status !== 200 || !isPlainObject(md.json)) throw new WalletError("ISSUER_REFUSED", `issuer metadata answered ${md.status}`);
    const meta = md.json;
    const credentialEndpoint = sameOrigin(meta.credential_endpoint);
    const nonceEndpoint = sameOrigin(meta.nonce_endpoint);
    const configs = isPlainObject(meta.credential_configurations_supported) ? meta.credential_configurations_supported : {};
    const issuerBatch = isPlainObject(meta.batch_credential_issuance) && typeof meta.batch_credential_issuance.batch_size === "number" ? meta.batch_credential_issuance.batch_size : 1;
    const authServer = Array.isArray(meta.authorization_servers) && typeof meta.authorization_servers[0] === "string" ? meta.authorization_servers[0] : issuer;
    const as = await this.core.getJson(new URL(`/.well-known/oauth-authorization-server${new URL(sameOrigin(authServer)).pathname.replace(/\/$/, "")}`, authServer).href);
    if (as.status !== 200 || !isPlainObject(as.json)) throw new WalletError("ISSUER_REFUSED", `authorization server metadata answered ${as.status}`);
    // The holder contract requires anonymous pre-authorized access: no client id is ever sent.
    if (as.json["pre-authorized_grant_anonymous_access_supported"] !== true) throw new WalletError("ISSUER_REFUSED", "the issuer would need a client id");
    const tokenEndpoint = sameOrigin(as.json.token_endpoint);

    const grant = offer.grants[PRE_AUTH] as Record<string, unknown>;
    const token = await this.core.postForm(tokenEndpoint, {
      grant_type: PRE_AUTH,
      "pre-authorized_code": grant["pre-authorized_code"] as string,
      ...(opts.txCode !== undefined ? { tx_code: opts.txCode } : {}),
    });
    const accessToken = isPlainObject(token.json) ? token.json.access_token : undefined;
    if (token.status !== 200 || typeof accessToken !== "string") {
      throw new WalletError("ISSUER_REFUSED", `token endpoint answered ${token.status}${isPlainObject(token.json) ? ` ${String(token.json.error)}` : ""}`);
    }

    // Only now, with a live token, are keys made — so a refused offer changes nothing.
    const relationship = await this.core.relationships.ensureKey(await this.core.relationships.ensure(view.counterparty));
    const copyKeys: string[] = [];
    const items: { record: HeldRecord; local: RecordLocal; needsKeep: boolean }[] = [];
    const unlistedIssuers = new Set<string>();
    try {
      for (const configId of offer.credential_configuration_ids) {
        const config = configs[configId];
        if (!isPlainObject(config)) throw new WalletError("ISSUER_REFUSED", `no configuration ${configId}`);
        const format = config.format;
        // d62(d)3: a credential shown to more than one viewer is shown through copies — so
        // every SD-JWT a door may read arrives as a batch, one key per future viewer.
        const isCopyBatch = format === "dc+sd-jwt" && config.vct !== THANK_YOU_VCT;
        const keyIds: string[] = [];
        if (isCopyBatch) {
          const n = Math.max(1, Math.min(this.core.batchSize, issuerBatch));
          for (let i = 0; i < n; i++) {
            const k = await this.core.keys.create("copy");
            copyKeys.push(k.keyId);
            keyIds.push(k.keyId);
          }
        } else {
          keyIds.push(relationship.keyId);
        }

        const nonceRes = await this.core.send({ url: nonceEndpoint, method: "POST", headers: {}, body: null }, []);
        const cNonce = isPlainObject(nonceRes.json) ? nonceRes.json.c_nonce : undefined;
        if (nonceRes.status !== 200 || typeof cNonce !== "string") throw new WalletError("ISSUER_REFUSED", `nonce endpoint answered ${nonceRes.status}`);
        const proofs: string[] = [];
        for (const keyId of keyIds) {
          proofs.push(
            await this.core.keys.withSigner(keyId, (s) =>
              signJws({ typ: PROOF_TYP, kid: s.did }, { aud: issuer, iat: this.core.now(), nonce: cNonce }, s),
            ),
          );
        }
        const credRes = await this.core.postJson(
          credentialEndpoint,
          { credential_configuration_id: configId, proofs: { jwt: proofs } },
          await this.core.allowed(keyIds),
          { authorization: `Bearer ${accessToken}` },
        );
        if (credRes.status !== 200 || !isPlainObject(credRes.json) || !Array.isArray(credRes.json.credentials)) {
          throw new WalletError("ISSUER_REFUSED", `credential endpoint answered ${credRes.status}`);
        }
        const declared = typeof credRes.json.kash_retention_until === "number" ? credRes.json.kash_retention_until : null;
        const copyGroup = isCopyBatch ? bytesToHex(await this.core.random(8)) : null;
        const usedCopies = new Set<string>();

        for (const c of credRes.json.credentials) {
          const value = isPlainObject(c) ? c.credential : undefined;
          let artifact: HeldArtifact;
          let boundKey: string;
          if (format === "dc+sd-jwt") {
            if (typeof value !== "string") throw new WalletError("RECORD_REFUSED", "an SD-JWT credential is a string");
            const parsed = parseSdJwt(value);
            const claims = parsed === null ? null : decodeJws(parsed.issuerJwt)?.payload ?? null;
            const cnf = claims !== null && isPlainObject(claims.cnf) ? claims.cnf : null;
            const holder = cnf === null ? null : didOfJwk(cnf.jwk);
            // Bound to a key this wallet made for this very request — or not kept.
            if (holder === null || !keyIds.includes(holder) || usedCopies.has(holder)) throw new WalletError("RECORD_REFUSED", "the credential is not bound to a key sent for it");
            usedCopies.add(holder);
            boundKey = holder;
            artifact = { kind: "sd-jwt", value };
            if (claims?.vct === THANK_YOU_VCT) {
              const ty = await verifyThankYou(value, { resolveKey: await this.core.trust.resolver(), nowSec: this.core.now() });
              if (!ty.ok) throw new WalletError("RECORD_REFUSED", `thank-you refused: ${ty.reason}`);
            }
          } else if (format === "kash-artifact") {
            const kind = detectKind(value);
            if (kind === null || kind === "sd-jwt") throw new WalletError("RECORD_REFUSED", "not an artifact this wallet can hold");
            boundKey = relationship.keyId;
            artifact = { kind, value };
          } else {
            throw new WalletError("RECORD_REFUSED", `format ${String(format)} is not supported`);
          }
          const built = await this.core.records.build(artifact, { relationship: boundKey, declaredRetention: declared, keepUnlisted: opts.keepUnlisted === true });
          if (built.status === "refused") throw new WalletError("RECORD_REFUSED", built.reasons.join(", "));
          if (built.status === "needs-keep-choice") unlistedIssuers.add(built.issuer);
          items.push({
            record: built.record,
            local: { counterparty: view.counterparty, boundKey, copyGroup, assignedVerifier: null },
            needsKeep: built.status === "needs-keep-choice",
          });
        }
        // Copy keys the issuer did not use are not kept.
        for (const k of keyIds) if (isCopyBatch && !usedCopies.has(k)) await this.core.keys.remove(k);
      }
    } catch (e) {
      for (const k of copyKeys) await this.core.keys.remove(k);
      throw e;
    }

    const pending: PendingRecords = { counterparty: view.counterparty, unlistedIssuers: [...unlistedIssuers], items, copyKeys };
    if (unlistedIssuers.size > 0) return { status: "needs-keep-choice", pending };
    return { status: "stored", slots: await this.keepAll(pending) };
  }

  /** The holder chose to keep records from a sender no pinned list names. They show as unlisted. */
  async keep(pending: PendingRecords): Promise<ReceiveResult> {
    return { status: "stored", slots: await this.keepAll(pending) };
  }

  /** The holder chose not to keep them. Nothing of them remains — not even the keys made for them. */
  async discard(pending: PendingRecords): Promise<void> {
    for (const k of pending.copyKeys) await this.core.keys.remove(k);
  }

  private async keepAll(pending: PendingRecords): Promise<readonly string[]> {
    const slots: string[] = [];
    for (const item of pending.items) {
      let record = item.record;
      if (item.needsKeep) {
        const rebuilt = await this.core.records.build(record.artifact, {
          relationship: record.manifest.relationship,
          declaredRetention: record.manifest.retentionSource === "issuer-declared" ? record.manifest.expiresAtUnix : null,
          keepUnlisted: true,
        });
        if (rebuilt.status !== "ready") throw new WalletError("RECORD_REFUSED", rebuilt.status === "refused" ? rebuilt.reasons.join(", ") : "not ready");
        record = rebuilt.record;
      }
      slots.push(await this.core.records.hold(record, item.local));
    }
    return slots;
  }
}
