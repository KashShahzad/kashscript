/**
 * A root held by WebCrypto: a P-256 key made for key agreement only
 * (`deriveBits`), non-extractable, so no code — this package's included — can
 * read its private half or make it sign. Used by the web adapter (persisted in
 * the browser, labelled weaker) and the headless mode (in memory, practice only).
 */

import { buf } from "../crypto/bytes";
import type { HardwareRoot, RootInfo } from "../platform";

export async function newAgreementKeyPair(): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])) as CryptoKeyPair;
}

export async function softwareRoot(pair: CryptoKeyPair, info: RootInfo): Promise<HardwareRoot> {
  if (pair.privateKey.extractable) throw new Error("the root's private key must be non-extractable");
  if (pair.privateKey.usages.some((u) => u !== "deriveBits")) throw new Error("the root agrees keys and does nothing else");
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return {
    info: () => info,
    publicKey: () => publicKey.slice(),
    agree: async (peer: Uint8Array) => {
      const peerKey = await crypto.subtle.importKey("raw", buf(peer), { name: "ECDH", namedCurve: "P-256" }, false, []);
      return new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: peerKey }, pair.privateKey, 256));
    },
  };
}
