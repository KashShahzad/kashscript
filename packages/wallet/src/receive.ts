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
 *
 * The authorisation-code grant (RW-16, 2026-11-23, at the founder's ruling):
 * the wallet reads an offer that carries it, or starts from a place the person
 * picks, and sends a pushed authorisation request (RFC 9126) with PKCE S256 as
 * a public client. Its `client_id` is random, made for that one request, never
 * stored and never reused — OAuth needs one, and it names nothing. **No wallet
 * attestation is ever sent** (KS-C1 R1): a place that requires it refuses, and
 * the wallet says so. Opening the authorisation page, the code exchange, DPoP
 * and the credential request after it are not built in this version.
 */

import { THANK_YOU_VCT, verifyThankYou } from "@kashscript/attest/exchange";
import { decodeJws, didOfJwk, parseSdJwt, signJws } from "@kashscript/attest/sd-jwt";
import type { HeldArtifact, HeldRecord } from "@kashscript/attest/holder";
import { buf, bytesToBase64Url, bytesToHex, utf8 } from "./crypto/bytes";
import type { WalletCore } from "./core";
import { WalletError } from "./errors";
import { detectKind, type RecordLocal } from "./records";
import { counterpartyOf, type ProofChoice } from "./relationships";

const PRE_AUTH = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
const AUTH_CODE = "authorization_code";
const PROOF_TYP = "openid4vci-proof+jwt";

export type OfferGrant = "pre-authorized_code" | "authorization_code";

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
  /** Which grant the offer carries. The pre-authorized one wins when both are there: it sends nothing about the wallet. */
  readonly grant: OfferGrant;
}

export interface AcceptOptions {
  readonly txCode?: string;
  readonly keepUnlisted?: boolean;
  /** For a start from a place the person picked: which of its records to ask for. Default: all it offers. */
  readonly configurationIds?: readonly string[];
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

function grantOf(offer: CredentialOffer): OfferGrant | null {
  const pre = offer.grants[PRE_AUTH];
  if (isPlainObject(pre) && typeof pre["pre-authorized_code"] === "string") return "pre-authorized_code";
  const code = offer.grants[AUTH_CODE];
  if (isPlainObject(code) && (code.issuer_state === undefined || typeof code.issuer_state === "string") && (code.authorization_server === undefined || typeof code.authorization_server === "string")) {
    return "authorization_code";
  }
  return null;
}

function asOffer(v: unknown): CredentialOffer {
  if (
    !isPlainObject(v) ||
    httpsOrigin(v.credential_issuer) === null ||
    !Array.isArray(v.credential_configuration_ids) ||
    v.credential_configuration_ids.length === 0 ||
    !v.credential_configuration_ids.every((c) => typeof c === "string") ||
    !isPlainObject(v.grants) ||
    grantOf(v as unknown as CredentialOffer) === null
  ) {
    throw new WalletError("OFFER_INVALID", "not an OID4VCI credential offer with a pre-authorized or authorization-code grant");
  }
  return v as unknown as CredentialOffer;
}

/** RFC 8414 §3.1 path insertion, which OpenID4VCI ≥ draft 16 uses for both documents (KS-C1 W1). */
function wellKnown(identifier: string, doc: "openid-credential-issuer" | "oauth-authorization-server"): string {
  const u = new URL(identifier);
  const path = doc === "openid-credential-issuer" ? u.pathname.replace(/^\/$/, "") : u.pathname.replace(/\/$/, "");
  return new URL(`/.well-known/${doc}${path}`, identifier).href;
}

const random64 = async (core: WalletCore, n: number): Promise<string> => bytesToBase64Url(await core.random(n));

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
    const grant = offer === null ? null : grantOf(offer);
    const pre = offer === null ? null : offer.grants[PRE_AUTH];
    return {
      offer,
      offerUri,
      counterparty,
      proof,
      needsTxCode: grant === "pre-authorized_code" && isPlainObject(pre) && pre.tx_code !== undefined,
      // An offer by reference not yet opened has no grant to read; it is opened again before it is redeemed.
      grant: grant ?? "pre-authorized_code",
    };
  }

  /**
   * Start from a place the person picked, with no offer in hand (OpenID4VCI's
   * wallet-initiated flow). Like `open`, it sends nothing unless keeping
   * records with that place is already on; then it reads the place's own
   * metadata, and only from there. The view lists what the place offers.
   */
  async start(issuerUrl: string): Promise<OfferView> {
    if (httpsOrigin(issuerUrl) === null) throw new WalletError("OFFER_INVALID", "a place is started from its https address");
    const counterparty = counterpartyOf(issuerUrl);
    const proof = await this.core.relationships.proof(counterparty);
    const base = { offerUri: null, counterparty, proof, needsTxCode: false, grant: "authorization_code" as const };
    if (proof !== "on") return { ...base, offer: null };
    const md = await this.core.getJson(wellKnown(issuerUrl, "openid-credential-issuer"));
    if (md.status !== 200 || !isPlainObject(md.json)) throw new WalletError("ISSUER_REFUSED", `issuer metadata answered ${md.status}`);
    if (md.json.credential_issuer !== issuerUrl) throw new WalletError("OFFER_ORIGIN", "the metadata names another issuer");
    const ids = isPlainObject(md.json.credential_configurations_supported) ? Object.keys(md.json.credential_configurations_supported) : [];
    if (ids.length === 0) throw new WalletError("ISSUER_REFUSED", "the place offers no records");
    return { ...base, offer: { credential_issuer: issuerUrl, credential_configuration_ids: ids, grants: { [AUTH_CODE]: {} } } };
  }

  /** Redeem an opened offer. Gated by the switch; a no, or no answer yet, sends nothing. */
  async accept(view: OfferView, opts: AcceptOptions = {}): Promise<ReceiveResult> {
    const proof = await this.core.relationships.proof(view.counterparty);
    if (proof === "unset") return { status: "needs-choice", counterparty: view.counterparty };
    if (proof === "off") return { status: "off" };
    if (view.offer === null) throw new WalletError("OFFER_INVALID", "open the offer again now that records are on");
    let offer = view.offer;
    if (opts.configurationIds !== undefined) {
      const ids = opts.configurationIds.filter((id) => offer.credential_configuration_ids.includes(id));
      if (ids.length === 0) throw new WalletError("OFFER_INVALID", "none of those records is offered");
      offer = { ...offer, credential_configuration_ids: ids };
    }
    const issuer = offer.credential_issuer;
    const origin = counterpartyOf(issuer);
    const sameOrigin = (url: unknown): string => {
      if (httpsOrigin(url) !== origin) throw new WalletError("OFFER_ORIGIN", `endpoint ${String(url)} is not on ${origin}`);
      return url as string;
    };

    const md = await this.core.getJson(wellKnown(issuer, "openid-credential-issuer"));
    if (md.status !== 200 || !isPlainObject(md.json)) throw new WalletError("ISSUER_REFUSED", `issuer metadata answered ${md.status}`);
    const meta = md.json;
    // OpenID4VCI §12.2.2 and RFC 8414 §3.3: a document that names another identifier than the one it was asked for is not used.
    if (meta.credential_issuer !== issuer) throw new WalletError("OFFER_ORIGIN", "the issuer metadata names another issuer than the one asked");
    const credentialEndpoint = sameOrigin(meta.credential_endpoint);
    const configs = isPlainObject(meta.credential_configurations_supported) ? meta.credential_configurations_supported : {};
    const issuerBatch = isPlainObject(meta.batch_credential_issuance) && typeof meta.batch_credential_issuance.batch_size === "number" ? meta.batch_credential_issuance.batch_size : 1;
    const listed = Array.isArray(meta.authorization_servers) ? meta.authorization_servers.filter((s): s is string => typeof s === "string") : [];
    const named = grantOf(offer) === "authorization_code" ? (offer.grants[AUTH_CODE] as Record<string, unknown>).authorization_server : undefined;
    if (typeof named === "string" && !listed.includes(named)) throw new WalletError("OFFER_INVALID", "the offer names an authorization server the metadata does not list");
    const authServer = typeof named === "string" ? named : (listed[0] ?? issuer);
    const as = await this.core.getJson(wellKnown(sameOrigin(authServer), "oauth-authorization-server"));
    if (as.status !== 200 || !isPlainObject(as.json)) throw new WalletError("ISSUER_REFUSED", `authorization server metadata answered ${as.status}`);
    if (as.json.issuer !== authServer) throw new WalletError("OFFER_ORIGIN", "the authorization server's metadata names another issuer than the one asked (RFC 8414 §3.3)");

    if (grantOf(offer) === "authorization_code") return this.pushAuthorisation(offer, configs, as.json, sameOrigin);

    const nonceEndpoint = sameOrigin(meta.nonce_endpoint);
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

  /**
   * The authorisation-code grant, as far as it is built: a pushed authorisation
   * request (RFC 9126) with PKCE S256 (RFC 7636), as a public client whose
   * `client_id` is random and made for this request alone. Never an
   * attestation header (KS-C1 R1). No key is made and nothing is stored: if the
   * place takes the request, the next step — opening its authorisation page —
   * is not built yet, and the wallet says so.
   */
  private async pushAuthorisation(
    offer: CredentialOffer,
    configs: Record<string, unknown>,
    as: Record<string, unknown>,
    sameOrigin: (url: unknown) => string,
  ): Promise<never> {
    const redirectUri = this.core.authorizationRedirectUri;
    if (redirectUri === null) throw new WalletError("NOT_BUILT", "this wallet has no address to come back to after an authorisation page");
    if (as.pushed_authorization_request_endpoint === undefined) throw new WalletError("NOT_BUILT", "the place takes only plain authorisation requests; pushed ones are what is built");
    const par = sameOrigin(as.pushed_authorization_request_endpoint);
    sameOrigin(as.authorization_endpoint);
    const methods = as.code_challenge_methods_supported;
    if (Array.isArray(methods) && !methods.includes("S256")) throw new WalletError("ISSUER_REFUSED", "the place does not take PKCE S256");

    const verifier = await random64(this.core, 32);
    const challenge = bytesToBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", buf(utf8(verifier)))));
    const scopes: string[] = [];
    const details: { type: "openid_credential"; credential_configuration_id: string }[] = [];
    for (const id of offer.credential_configuration_ids) {
      const c = configs[id];
      if (!isPlainObject(c)) throw new WalletError("ISSUER_REFUSED", `no configuration ${id}`);
      if (typeof c.scope === "string" && c.scope.length > 0) scopes.push(c.scope);
      else details.push({ type: "openid_credential", credential_configuration_id: id });
    }
    const code = offer.grants[AUTH_CODE] as Record<string, unknown>;
    const res = await this.core.postForm(par, {
      response_type: "code",
      client_id: await random64(this.core, 16),
      redirect_uri: redirectUri,
      code_challenge: challenge,
      code_challenge_method: "S256",
      state: await random64(this.core, 16),
      ...(typeof code.issuer_state === "string" ? { issuer_state: code.issuer_state } : {}),
      ...(scopes.length > 0 ? { scope: scopes.join(" ") } : {}),
      ...(details.length > 0 ? { authorization_details: JSON.stringify(details) } : {}),
    });
    const body = isPlainObject(res.json) ? res.json : {};
    if ((res.status === 201 || res.status === 200) && typeof body.request_uri === "string") {
      throw new WalletError("NOT_BUILT", "the place took the pushed request; opening its authorisation page is not built in this version");
    }
    throw new WalletError("ISSUER_REFUSED", `pushed authorisation request answered ${res.status}${typeof body.error === "string" ? ` ${body.error}` : ""}`);
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
