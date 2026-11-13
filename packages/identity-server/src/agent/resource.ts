// ============================================================================
// @kashscript/identity-server — RFC 8707 Resource Indicator canonicalization
// ----------------------------------------------------------------------------
// The `resource` an MCP client requests becomes the access token's `aud`
// (audience). RFC 8707 §2: the resource MUST be an absolute URI and MUST NOT
// include a fragment. To prevent audience-mismatch false-negatives, both the
// minted `aud` and the resource server's expected identifier are run through
// the same canonicalization: lowercase scheme + host, drop the default port,
// and drop a bare trailing-slash path.
// ============================================================================

import { KashscriptIdentityMalformedPayloadError } from "../errors";

const DEFAULT_PORTS: Readonly<Record<string, string>> = { "http:": "80", "https:": "443" };

/**
 * Canonicalizes an RFC 8707 resource URI into the form used as the token `aud`.
 *
 * - scheme + host lowercased
 * - default port for the scheme removed
 * - a path of exactly "/" collapsed to "" (no bare trailing slash)
 * - query preserved; fragment rejected
 *
 * @throws KashscriptIdentityMalformedPayloadError if the URI is not absolute
 *         or carries a fragment.
 */
export function canonicalizeResourceUri(uri: string): string {
  if (typeof uri !== "string" || uri.length === 0) {
    throw new KashscriptIdentityMalformedPayloadError("resource");
  }
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch (err) {
    throw new KashscriptIdentityMalformedPayloadError("resource", err);
  }
  // RFC 8707 §2: the resource MUST NOT include a fragment component.
  if (parsed.hash.length > 0) {
    throw new KashscriptIdentityMalformedPayloadError("resource (must not contain a fragment)");
  }
  const scheme = parsed.protocol.toLowerCase();
  const host = parsed.hostname.toLowerCase();
  const port = parsed.port && parsed.port !== DEFAULT_PORTS[scheme] ? `:${parsed.port}` : "";
  const path = parsed.pathname === "/" ? "" : parsed.pathname;
  return `${scheme}//${host}${port}${path}${parsed.search}`;
}

/**
 * Asserts that `uri` is a valid RFC 8707 resource identifier (absolute, no
 * fragment). Returns the canonical form.
 */
export function assertCanonicalResourceUri(uri: string): string {
  return canonicalizeResourceUri(uri);
}

/** Whether two resource URIs denote the same audience after canonicalization. */
export function resourceUriEquals(a: string, b: string): boolean {
  try {
    return canonicalizeResourceUri(a) === canonicalizeResourceUri(b);
  } catch {
    return false;
  }
}
