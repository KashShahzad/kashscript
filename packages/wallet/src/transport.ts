/**
 * The only way out, and the guard in front of it.
 *
 * Nothing that could link one relationship to another leaves the device
 * (d41; d47(g)): not the hardware root's public key, not another place's key
 * or mailbox token, not a copy key shown elsewhere. Every request passes a
 * guard that knows every identifier the wallet holds and refuses — before
 * sending — any request carrying one it was not built to carry. The guard
 * reads inside form fields and base64url segments (JWTs, SD-JWTs), not just
 * the raw text. It is the second line: requests are built from one
 * relationship's keys in the first place.
 *
 * The real transport sends no cookies, no referrer, caches nothing and follows
 * no redirect — a redirect could carry a request to a third party. There is no
 * push token, install id or account id anywhere in this package: a shared push
 * token would let a relay link a person's relationships, so the component
 * takes none. A relay reaches a person through one mailbox token per relationship.
 */

import { base64UrlToBytes, utf8Decode } from "./crypto/bytes";
import { WalletError } from "./errors";
import type { HttpRequest, HttpResponse, Transport } from "./platform";

/** `fetch` with no cookies, referrer, cache or redirects. */
export function fetchTransport(fetchImpl: typeof fetch = globalThis.fetch): Transport {
  return async (req) => {
    const res = await fetchImpl(req.url, {
      method: req.method,
      headers: { ...req.headers },
      ...(req.body !== null ? { body: req.body } : {}),
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
      cache: "no-store",
    });
    return { status: res.status, text: await res.text() };
  };
}

/** Everything a request is read as: the raw text, form fields decoded, base64url segments decoded. */
export function readings(req: HttpRequest): string {
  const parts = [req.url, JSON.stringify(req.headers), req.body ?? ""];
  const text = parts.join("\n");
  const decoded: string[] = [];
  try {
    decoded.push(decodeURIComponent(text.replace(/\+/g, " ")));
  } catch {
    /* not percent-encoded */
  }
  for (const seg of (text + "\n" + decoded.join("\n")).split(/[^A-Za-z0-9_-]+/)) {
    if (seg.length < 16) continue;
    try {
      const t = utf8Decode(base64UrlToBytes(seg));
      if (t !== null && /^[\x09\x0a\x0d\x20-\x7e]*$/.test(t)) decoded.push(t);
    } catch {
      /* not base64url */
    }
  }
  return [text, ...decoded].join("\n");
}

export interface Identifiers {
  /** Every identifier the wallet holds, in every encoding it could appear in. */
  readonly all: readonly string[];
}

/**
 * Send one request, allowed to carry only `allow`. Throws before sending if it
 * carries any other identifier the wallet holds, if it is not https, or if
 * there is no transport.
 */
export async function guardedSend(
  transport: Transport | null,
  req: HttpRequest,
  identifiers: Identifiers,
  allow: readonly string[],
): Promise<HttpResponse> {
  if (!req.url.startsWith("https://")) throw new WalletError("NOT_HTTPS", req.url);
  const allowed = new Set(allow);
  const text = readings(req);
  const leaked = identifiers.all.find((id) => id.length >= 16 && !allowed.has(id) && text.includes(id));
  if (leaked !== undefined) throw new WalletError("IDENTIFIER_LEAK", `the request to ${new URL(req.url).origin} carried an identifier from another relationship`);
  if (transport === null) throw new WalletError("OFFLINE");
  try {
    return await transport(req);
  } catch (e) {
    throw new WalletError("SEND_FAILED", e instanceof Error ? e.message : String(e));
  }
}
