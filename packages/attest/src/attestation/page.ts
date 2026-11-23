/**
 * The page's seal (RW-15; `specs/attestation/README.md` §2.4b): how a proof page keeps **the artefact for the
 * holder of the disclosure alone**.
 *
 * A page is made for one viewer from a copy that discloses the record. The host stores the copy's issuer JWT —
 * the salted commitments, and nothing that joins — and the artefact **sealed under the `record` disclosure**:
 * a JWE in compact serialization (RFC 7516), `alg: dir`, `enc: A256GCM` (RFC 7518), its key HKDF-SHA-256
 * (RFC 5869) over the disclosure's bytes with the info `kash-page-artefact-v1`. The link's fragment carries the
 * disclosures, which never reach the host. So the host serves the same bytes to anyone, learns from a view which
 * record it opened from nothing, and a leaked store holds commitments and ciphertext; only the holder of the
 * disclosure — its salt is 128 random bits — reads the artefact, and `shownOnPage` then checks the opened
 * artefact against the commitment. WebCrypto only, so it runs in the viewer's browser.
 *
 * What it does not do: hide the token the host maps to a page, or the issuer's own bookkeeping of which records
 * a page shows (§3 G1's bound). A leaked link is a holder.
 */

import { AttestError } from "../errors";
import { base64UrlToBytes, bytesToBase64Url } from "../ed25519";
import { decodeDisclosure, parseSdJwt } from "../sd-jwt/sd-jwt";
import { shownOnPage, type PageOptions, type PageView } from "./copies";

/** The HKDF info: the one purpose a disclosure's bytes are stretched for. */
export const PAGE_SEAL_INFO = "kash-page-artefact-v1" as const;
/** The JWE protected header, exactly: a direct key, AES-256-GCM. */
export const PAGE_SEAL_HEADER = { alg: "dir", enc: "A256GCM" } as const;

const enc = new TextEncoder();
const dec = new TextDecoder();
const bs = (b: Uint8Array): BufferSource => b as unknown as BufferSource;
const PROTECTED_B64U = bytesToBase64Url(enc.encode(JSON.stringify(PAGE_SEAL_HEADER)));
const TAG_BYTES = 16;
const IV_BYTES = 12;

/** The AES-256-GCM key a disclosure opens: HKDF-SHA-256(IKM = the disclosure's bytes, salt = 32 zero bytes, info = {@link PAGE_SEAL_INFO}). */
export async function pageKeyOf(disclosure: string): Promise<CryptoKey> {
  const ikm = await crypto.subtle.importKey("raw", bs(enc.encode(disclosure)), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: bs(new Uint8Array(32)), info: bs(enc.encode(PAGE_SEAL_INFO)) },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** Seal an artefact (any JSON value) under a disclosure: a compact JWE, `<protected>..<iv>.<ciphertext>.<tag>`. */
export async function sealArtefact(disclosure: string, artefact: unknown): Promise<string> {
  const key = await pageKeyOf(disclosure);
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const plain = enc.encode(JSON.stringify(artefact));
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: bs(iv), additionalData: bs(enc.encode(PROTECTED_B64U)), tagLength: TAG_BYTES * 8 }, key, bs(plain)));
  const ciphertext = sealed.slice(0, sealed.length - TAG_BYTES);
  const tag = sealed.slice(sealed.length - TAG_BYTES);
  return `${PROTECTED_B64U}..${bytesToBase64Url(iv)}.${bytesToBase64Url(ciphertext)}.${bytesToBase64Url(tag)}`;
}

/** Open a sealed artefact with its disclosure. Null when it does not open: another disclosure, another header, changed bytes. Never throws. */
export async function openArtefact(disclosure: string, sealed: string): Promise<unknown> {
  try {
    const parts = sealed.trim().split(".");
    if (parts.length !== 5 || parts[1] !== "") return null;
    const [protectedB64u, , ivB64u, ctB64u, tagB64u] = parts as [string, string, string, string, string];
    const header: unknown = JSON.parse(dec.decode(base64UrlToBytes(protectedB64u)));
    if (typeof header !== "object" || header === null || Array.isArray(header)) return null;
    const h = header as Record<string, unknown>;
    if (h.alg !== PAGE_SEAL_HEADER.alg || h.enc !== PAGE_SEAL_HEADER.enc || Object.keys(h).length !== 2) return null;
    const iv = base64UrlToBytes(ivB64u);
    const ciphertext = base64UrlToBytes(ctB64u);
    const tag = base64UrlToBytes(tagB64u);
    if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) return null;
    const joined = new Uint8Array(ciphertext.length + tag.length);
    joined.set(ciphertext, 0);
    joined.set(tag, ciphertext.length);
    const key = await pageKeyOf(disclosure);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: bs(iv), additionalData: bs(enc.encode(protectedB64u)), tagLength: TAG_BYTES * 8 }, key, bs(joined));
    return JSON.parse(dec.decode(new Uint8Array(plain))) as unknown;
  } catch {
    return null;
  }
}

/** A page's three parts: what the host stores (`copy`, `artefact`) and what only the link's fragment carries (`fragment`). */
export interface PageParts {
  /** The copy's issuer JWT, `<jwt>~`: the commitments, and nothing that joins. */
  readonly copy: string;
  /** Every disclosure, `<d>~…`: carried in the link's fragment, never sent to the host. */
  readonly fragment: string;
  /** The artefact, sealed under the `record` disclosure. */
  readonly artefact: string;
}

/** The disclosure that opens a copy's record, or null when the copy discloses none. */
export async function recordDisclosureOf(copy: string): Promise<string | null> {
  const parsed = parseSdJwt(copy);
  if (parsed === null) return null;
  for (const d of parsed.disclosures) {
    const decoded = await decodeDisclosure(d);
    if (decoded?.name === "record") return d;
  }
  return null;
}

/** Make a page from a held copy (every disclosure, no key binding) and the artefact it is a copy of. */
export async function pageOf(heldCopy: string, artefact: unknown): Promise<PageParts> {
  const parsed = parseSdJwt(heldCopy);
  if (parsed === null) throw new AttestError("INVALID_INPUT", "a page is made from an SD-JWT copy");
  if (parsed.kbJwt !== null) throw new AttestError("INVALID_INPUT", "a page is made from the held copy, never from a presentation");
  const disclosure = await recordDisclosureOf(heldCopy);
  if (disclosure === null) throw new AttestError("INVALID_INPUT", "the copy discloses no record — there is nothing to seal the artefact under");
  return {
    copy: `${parsed.issuerJwt}~`,
    fragment: parsed.disclosures.map((d) => `${d}~`).join(""),
    artefact: await sealArtefact(disclosure, artefact),
  };
}

/** What the viewer's browser holds: the stored copy with the fragment's disclosures — the held form again. */
export const viewerCopyOf = (stored: string, fragment: string): string => `${stored.trim()}${fragment.trim()}`;

/**
 * Open a page as its viewer does: put the fragment's disclosures back on the copy, open the seal with the
 * `record` disclosure, and apply the page's rule. Without the fragment the artefact stays sealed and
 * `shownOnPage` shows nothing; with it, the opened artefact is checked against the commitment.
 */
export async function openPage(parts: PageParts, opts: PageOptions = {}): Promise<PageView> {
  const copy = viewerCopyOf(parts.copy, parts.fragment);
  const disclosure = await recordDisclosureOf(copy);
  const opened = disclosure === null ? null : await openArtefact(disclosure, parts.artefact);
  return shownOnPage(copy, opened === null ? [] : [opened], opts);
}
