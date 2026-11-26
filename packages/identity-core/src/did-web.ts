/**
 * did:web — the standard identifier of an organisation on its own domain
 * (RW-19 branch B; d91(e), d97(h), d71's *no format of our own*).
 *
 * Where a stranger must resolve an identifier, a standard method is used:
 * an organisation is `did:web:<its-domain>`, and its public records are DID
 * URLs under it — `did:web:<domain>/place/<slug>` keeps d60(a)'s shape, *the
 * publisher's DID plus a path*, under a method any stranger resolves.
 *
 * This module is grammar and derivation only. **Nothing here fetches** (d28;
 * the attestation profile §1.1): the kernel checks a `did:web` signer with a
 * key from a pinned trust list or a held key, and `didWebUrl` merely states
 * where the W3C method says that organisation's DID document lives, for the
 * caller who chooses to look.
 */

import { KashCryptoError } from "./errors";

/**
 * The shape of a `did:web` this ecosystem reads or writes, as a regex source
 * for schemas — one grammar, the one `kash.attestation@1.0.0` already
 * publishes: a lowercase host, an optional port written `%3A<port>`, and up
 * to eight optional path segments written with colons (the W3C method's
 * form). A shape gate, not a hostname validator.
 */
export const DID_WEB_SOURCE =
  "did:web:[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?(?:%3A[0-9]{1,5})?(?::[A-Za-z0-9._-]{1,64}){0,8}";

const DID_WEB_RE = new RegExp(`^${DID_WEB_SOURCE}$`);
const DID_WEB_PREFIX = "did:web:";

/** The parts of a `did:web`: its host, its optional port, and its colon-path segments. */
export interface DidWebParts {
  readonly host: string;
  readonly port: number | null;
  readonly path: readonly string[];
}

/** True when the string is a `did:web` of the shape this ecosystem reads. Never throws. */
export function isDidWeb(value: string): boolean {
  return typeof value === "string" && DID_WEB_RE.test(value);
}

/**
 * Parse a `did:web` into host, port and path segments.
 *
 * @throws {@link KashCryptoError} (`INVALID_DID`) for anything the grammar refuses.
 */
export function parseDidWeb(did: string): DidWebParts {
  if (typeof did !== "string" || !DID_WEB_RE.test(did)) {
    throw new KashCryptoError(`Not a did:web this ecosystem reads: ${JSON.stringify(did)}.`, "INVALID_DID");
  }
  const [authority, ...path] = did.slice(DID_WEB_PREFIX.length).split(":") as [string, ...string[]];
  const percent = authority.indexOf("%3A");
  const host = percent === -1 ? authority : authority.slice(0, percent);
  const port = percent === -1 ? null : Number.parseInt(authority.slice(percent + 3), 10);
  return { host, port, path };
}

/**
 * The https URL the W3C `did:web` method resolves this DID to — derivation
 * only, never a fetch: the host (and port), the colon-path as path segments,
 * then `/did.json`, or `/.well-known/did.json` when there is no path.
 */
export function didWebUrl(did: string): string {
  const { host, port, path } = parseDidWeb(did);
  const authority = port === null ? host : `${host}:${port}`;
  return path.length === 0
    ? `https://${authority}/.well-known/did.json`
    : `https://${authority}/${path.join("/")}/did.json`;
}
