// did:kash sovereign identity binding, over @kashscript/identity-core.
//
// A sovereign identity is a did:kash (key-only, no directory). The atproto repo
// it publishes to has its own did:plc — hosting plumbing. The two are bound by
// a signed binding record in the repo: a KashEvent the holder signs with its
// did:kash attesting "this atproto did is mine". Trust labels and certificates
// reference the did:kash; the binding survives PDS migration (the did:plc can
// change, the did:kash never does).
//
// Ported from the @indus/muffler seed (M3, ADR-0016). The venture-branded NSID
// + DST (app.indusland.org.identity / indus.org.identity.v1) are parameterized
// so the binding is venture-neutral; a venture passes its own for wire-compat
// with existing binding records.

import {
  deriveDid,
  exportKey,
  generateKeyPair,
  parseDid,
  signEvent,
  verifyEvent,
} from "@kashscript/identity-core";
import type {
  ExportedKey,
  KashDid,
  KashKeyPair,
  SignedKashEvent,
} from "@kashscript/identity-core";

/** Neutral default NSID for the atproto-binding record's `header.typ`. */
export const KASH_ATPROTO_BINDING_NSID = "kash.identity.atproto-binding";
/** Neutral default domain-separation tag for the binding signature. */
export const KASH_ATPROTO_BINDING_DST = "kash.identity.atproto-binding.v1\n";

/** Overrides for the binding record's NSID / DST (a venture supplies its own
 *  to stay wire-compatible with binding records it already published). */
export interface OrgBindingOptions {
  readonly nsid?: string;
  readonly dst?: string;
}

export interface OrgIdentity {
  did: KashDid;
  keyPair: KashKeyPair;
  exported: ExportedKey;
}

/** Mint a fresh sovereign identity. The exported JWK is what a portal hands to
 *  passkey custody (identity-sdk) — never persisted server-side in cleartext. */
export async function mintOrgIdentity(): Promise<OrgIdentity> {
  const keyPair = await generateKeyPair();
  return {
    did: deriveDid(keyPair.publicKey),
    keyPair,
    exported: exportKey(keyPair),
  };
}

/** Sign the binding record that attests `atprotoDid` belongs to the holder's
 *  did:kash. The DST is embedded in the signature, so `verifyOrgBindingRecord`
 *  needs no DST argument. */
export async function createOrgBindingRecord(
  keyPair: KashKeyPair,
  atprotoDid: string,
  boundAt: string,
  opts: OrgBindingOptions = {},
): Promise<SignedKashEvent> {
  const nsid = opts.nsid ?? KASH_ATPROTO_BINDING_NSID;
  const dst = opts.dst ?? KASH_ATPROTO_BINDING_DST;
  const did = deriveDid(keyPair.publicKey);
  const kid = `${did}#sig-1`;
  const header = { typ: nsid, v: 1, iss: did, kid };
  const body = { atprotoDid, boundAt };
  const signature = await signEvent(header, body, keyPair.privateKey, { dst, kid });
  return { header, body, signature };
}

/** Verify a binding record resolves to the claimed did:kash AND binds the
 *  expected atproto did. The point: an app-view can trust an atproto repo
 *  belongs to a sovereign identity without asking any server (key-only DID
 *  resolution). */
export async function verifyOrgBindingRecord(
  record: SignedKashEvent,
  kashDid: string,
  expectedAtprotoDid: string,
): Promise<boolean> {
  let publicKey: Uint8Array;
  try {
    publicKey = parseDid(kashDid);
  } catch {
    return false;
  }
  const body = record.body as { atprotoDid?: unknown } | null;
  if (!body || body.atprotoDid !== expectedAtprotoDid) return false;
  return verifyEvent(record, publicKey);
}
