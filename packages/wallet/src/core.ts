/**
 * The pieces every part of the wallet shares, and the one guarded way out.
 */

import { decompressP256PublicKey } from "@kashscript/identity-core";
import type { Copy } from "./copy";
import { bytesToBase64, bytesToBase64Url, bytesToHex, base64UrlToBytes } from "./crypto/bytes";
import type { KeyRegistry } from "./keys";
import type { PresentationLog } from "./log";
import type { Clock, HardwareRoot, HttpRequest, Random, Transport } from "./platform";
import type { Records } from "./records";
import type { Relationship, Relationships } from "./relationships";
import { guardedSend, type Identifiers } from "./transport";
import type { TrustStore } from "./trust";
import type { Vault } from "./vault";

export interface WalletConfig {
  /** Trust-list publishers pinned out of band. None by default: the app ships its publisher's identifier. */
  readonly pinnedPublishers?: readonly string[];
  /** Copies of a yes asked for at each handoff — one per future verifier. */
  readonly batchSize?: number;
  readonly copy?: Partial<Copy>;
}

export interface JsonResponse {
  readonly status: number;
  readonly json: unknown;
}

export class WalletCore {
  constructor(
    readonly vault: Vault,
    readonly root: HardwareRoot,
    readonly keys: KeyRegistry,
    readonly relationships: Relationships,
    readonly records: Records,
    readonly trust: TrustStore,
    readonly log: PresentationLog,
    readonly copy: Copy,
    readonly random: Random,
    readonly now: Clock,
    readonly batchSize: number,
    readonly pinnedPublishers: readonly string[],
    private readonly transport: Transport | null,
  ) {}

  /** Every identifier the wallet holds, in each encoding a request could carry it in. */
  async identifiers(): Promise<Identifiers> {
    const all = new Set<string>();
    const root = this.root.publicKey();
    for (const s of [bytesToBase64Url(root), bytesToBase64(root), bytesToHex(root), bytesToBase64Url(root.slice(1, 33)), bytesToBase64Url(root.slice(33))]) all.add(s);
    for (const k of await this.keys.list()) for (const s of keyEncodings(k.keyId, k.publicKey)) all.add(s);
    for (const r of await this.relationships.list()) {
      all.add(r.mailbox);
      if (r.theirDid !== null) all.add(r.theirDid);
    }
    return { all: [...all] };
  }

  /** What one request may carry: these keys, and this relationship's own identifiers. */
  async allowed(keyIds: readonly string[], relationship: Relationship | null = null): Promise<readonly string[]> {
    const out: string[] = [];
    for (const id of keyIds) {
      const k = await this.keys.find(id);
      if (k !== null) out.push(...keyEncodings(k.keyId, k.publicKey));
    }
    if (relationship?.theirDid) out.push(relationship.theirDid);
    return out;
  }

  async send(req: HttpRequest, allow: readonly string[]): Promise<JsonResponse> {
    const res = await guardedSend(this.transport, req, await this.identifiers(), allow);
    let json: unknown = null;
    try {
      json = res.text.length > 0 ? JSON.parse(res.text) : null;
    } catch {
      json = null;
    }
    return { status: res.status, json };
  }

  getJson(url: string, allow: readonly string[] = []): Promise<JsonResponse> {
    return this.send({ url, method: "GET", headers: { accept: "application/json" }, body: null }, allow);
  }

  postForm(url: string, fields: Readonly<Record<string, string>>, allow: readonly string[] = [], headers: Readonly<Record<string, string>> = {}): Promise<JsonResponse> {
    return this.send(
      { url, method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", ...headers }, body: new URLSearchParams({ ...fields }).toString() },
      allow,
    );
  }

  postJson(url: string, body: unknown, allow: readonly string[] = [], headers: Readonly<Record<string, string>> = {}): Promise<JsonResponse> {
    return this.send({ url, method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) }, allow);
  }
}

/** A key as it could appear on the wire: its id (and a DID's bare body), its JWK `x` (and,
 *  for P-256, `y` and the uncompressed point), its hex. */
export function keyEncodings(keyId: string, publicKeyB64u: string): readonly string[] {
  const bytes = base64UrlToBytes(publicKeyB64u);
  const out = [keyId, publicKeyB64u, bytesToHex(bytes)];
  if (keyId.startsWith("did:kash:")) out.push(keyId.slice("did:kash:".length));
  if (bytes.length === 33) {
    const full = decompressP256PublicKey(bytes);
    out.push(bytesToBase64Url(full.slice(1, 33)), bytesToBase64Url(full.slice(33)), bytesToBase64Url(full), bytesToHex(full));
  }
  return out;
}
