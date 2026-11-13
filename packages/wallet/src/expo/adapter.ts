/**
 * The Expo / React Native platform, over the `KashWalletRoot` native module
 * (ios/, android/ in this package, autolinked by Expo). Pure TypeScript over
 * the module's interface, so it is tested with a stand-in module; the native
 * half compiles in an app's development build.
 *
 * The native module does three things:
 * - **the root** — a P-256 key made for key agreement only, in the Secure
 *   Enclave (iOS, CryptoKit's KeyAgreement key type) or the Android Keystore
 *   (`PURPOSE_AGREE_KEY`, StrongBox where present, Android 12+), used only
 *   after the face, fingerprint or screen lock. Neither type can sign, so the
 *   root cannot sign a record — the hardware refuses (d47(g)(1)).
 * - **signing keys** (PL-2) — separate P-256 keys made for signing only
 *   (CryptoKit's Signing type; `PURPOSE_SIGN`), one per place and one per copy
 *   of a yes, signing ES256 in the chip after the same unlock (d47(g)(2)). Their
 *   private halves never reach JavaScript; the wallet holds only their names.
 * - **a blob store** in the app's own private files, kept out of the phone's
 *   cloud backups, so nothing — not the sealed vault, not the switch — syncs
 *   anywhere.
 */

import { base64ToBytes, base64UrlToBytes, bytesToBase64, bytesToBase64Url, bytesToHex, buf, concat, utf8 } from "../crypto/bytes";
import type { Copy } from "../copy";
import type { BlobStore, HardwareRoot, HardwareSigners, RootInfo, RootProvider, RootWhere, Transport, WalletPlatform } from "../platform";
import { systemClock, systemRandom } from "../platform";
import { getInflate } from "@kashscript/attest/holder";

export type UnavailableReason = "no-secure-hardware" | "no-screen-lock" | "system-too-old";

export interface NativeAvailability {
  readonly available: boolean;
  readonly reason: UnavailableReason | null;
}

/** The native module's contract. Keys and secrets cross it as base64url; blobs as base64. */
export interface NativeRootModule {
  isAvailable(): Promise<NativeAvailability>;
  /** Make the root; returns its SEC1 public key. Refuses if one exists. */
  create(alias: string): Promise<string>;
  publicKey(alias: string): Promise<string | null>;
  /** Where the root lives, once made: "secure-enclave" | "strongbox" | "trusted-environment". */
  where(alias: string): Promise<string | null>;
  /** ECDH after the face, fingerprint or screen lock, showing `prompt`. Returns the shared secret. */
  agree(alias: string, peerPublicKey: string, prompt: string): Promise<string>;
  remove(alias: string): Promise<boolean>;
  /** PL-2: make a P-256 SIGNING key; returns its SEC1 public key (base64url) and where it lives. Never the root. */
  createSigningKey(alias: string): Promise<{ readonly publicKey: string; readonly where: string }>;
  /** ES256 over the message bytes (base64url), after the face, fingerprint or screen lock. Returns DER (base64url). */
  signWithKey(alias: string, message: string, prompt: string): Promise<string>;
  removeSigningKey(alias: string): Promise<boolean>;
  blobPut(name: string, base64: string): Promise<void>;
  blobGet(name: string): Promise<string | null>;
  blobDelete(name: string): Promise<void>;
  blobList(prefix: string): Promise<string[]>;
}

export const ROOT_ALIAS = "kash-wallet-root-1";

/** Plain words for why a phone can't hold the root. Never a quiet fall back to a weaker key. */
export function explainUnavailable(reason: UnavailableReason | null, copy: Copy): string {
  if (reason === "no-screen-lock") return copy.rootNeedsScreenLock;
  if (reason === "system-too-old") return copy.rootNeedsNewerSystem;
  return copy.rootNoSecureChip;
}

function whereOf(v: string | null): RootWhere {
  return v === "strongbox" || v === "trusted-environment" || v === "secure-enclave" ? v : "secure-enclave";
}

export function nativeRootProvider(native: NativeRootModule, copy: Copy): RootProvider {
  const make = async (publicKeyB64u: string): Promise<HardwareRoot> => {
    const publicKey = base64UrlToBytes(publicKeyB64u);
    if (publicKey.length !== 65 || publicKey[0] !== 0x04) throw new Error("the native root returned a malformed public key");
    const info: RootInfo = { strength: "hardware", where: whereOf(await native.where(ROOT_ALIAS)), unlock: "biometrics-or-pin", weaker: false, text: copy.rootHardware };
    return {
      info: () => info,
      publicKey: () => publicKey.slice(),
      agree: async (peer, prompt) => base64UrlToBytes(await native.agree(ROOT_ALIAS, bytesToBase64Url(peer), prompt)),
    };
  };
  return {
    open: async () => {
      const pk = await native.publicKey(ROOT_ALIAS);
      return pk === null ? null : make(pk);
    },
    create: async () => make(await native.create(ROOT_ALIAS)),
  };
}

export function nativeBlobStore(native: NativeRootModule): BlobStore {
  return {
    put: (name, bytes) => native.blobPut(name, bytesToBase64(bytes)),
    get: async (name) => {
      const b64 = await native.blobGet(name);
      return b64 === null ? null : base64ToBytes(b64);
    },
    delete: (name) => native.blobDelete(name),
    list: (prefix) => native.blobList(prefix),
  };
}

/** Signing keys in the secure chip (PL-2): each named by a random alias the vault keeps sealed. */
export function nativeSigners(native: NativeRootModule, copy: Copy): HardwareSigners {
  let where: RootWhere = "secure-enclave";
  return {
    info: () => ({ strength: "hardware", where, text: copy.rootHardware }),
    create: async () => {
      const alias = `kash-wallet-sign-${bytesToHex(await systemRandom(16))}`;
      const made = await native.createSigningKey(alias);
      const publicKey = base64UrlToBytes(made.publicKey);
      if (publicKey.length !== 65 || publicKey[0] !== 0x04) throw new Error("the native signing key came back malformed");
      where = whereOf(made.where);
      return { handle: alias, publicKey };
    },
    sign: async (handle, message, prompt) => base64UrlToBytes(await native.signWithKey(handle, bytesToBase64Url(message), prompt)),
    remove: async (handle) => {
      await native.removeSigningKey(handle);
    },
  };
}

export function nativePlatform(native: NativeRootModule, copy: Copy, transport: Transport | null): WalletPlatform {
  return { roots: nativeRootProvider(native, copy), store: nativeBlobStore(native), random: systemRandom, now: systemClock, transport, signers: nativeSigners(native, copy) };
}

export interface RuntimeCheck {
  readonly ok: boolean;
  /** Required and absent: the wallet refuses to start. */
  readonly missing: readonly string[];
  /** Absent but survivable: a status list can't be read, so status says "not checked". */
  readonly degraded: readonly string[];
}

const PKCS8_ED25519 = Uint8Array.of(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20);

async function probe(name: string, run: () => Promise<unknown>, missing: string[]): Promise<void> {
  try {
    await run();
  } catch {
    missing.push(name);
  }
}

/**
 * What the JavaScript runtime must provide. React Native has no WebCrypto of
 * its own; `react-native-quick-crypto` lists every algorithm below as
 * supported (⚠ verify the version at PL-9). Run before anything else.
 */
export async function checkRuntime(): Promise<RuntimeCheck> {
  const missing: string[] = [];
  const degraded: string[] = [];
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (c === undefined || c.subtle === undefined || typeof c.getRandomValues !== "function") {
    return { ok: false, missing: ["WebCrypto (crypto.subtle, crypto.getRandomValues)"], degraded };
  }
  const s = c.subtle;
  if (typeof TextEncoder === "undefined" || typeof TextDecoder === "undefined") missing.push("TextEncoder / TextDecoder");
  if (typeof atob !== "function" || typeof btoa !== "function") missing.push("atob / btoa");
  await probe("Ed25519 (PKCS8 import, sign)", async () => {
    const k = await s.importKey("pkcs8", buf(concat(PKCS8_ED25519, new Uint8Array(32).fill(7))), { name: "Ed25519" }, true, ["sign"]);
    await s.exportKey("jwk", k);
    await s.sign({ name: "Ed25519" }, k, buf(utf8("probe")));
  }, missing);
  await probe("ECDSA P-256 (verify ES256)", async () => {
    const k = (await s.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])) as CryptoKeyPair;
    const sig = await s.sign({ name: "ECDSA", hash: "SHA-256" }, k.privateKey, buf(utf8("probe")));
    await s.verify({ name: "ECDSA", hash: "SHA-256" }, k.publicKey, sig, buf(utf8("probe")));
  }, missing);
  await probe("ECDH P-256 (generate, deriveBits)", async () => {
    const a = (await s.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])) as CryptoKeyPair;
    const b = (await s.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])) as CryptoKeyPair;
    await s.deriveBits({ name: "ECDH", public: b.publicKey }, a.privateKey, 256);
    await s.exportKey("raw", a.publicKey);
  }, missing);
  await probe("AES-GCM", async () => {
    const k = await s.importKey("raw", buf(new Uint8Array(32)), { name: "AES-GCM" }, false, ["encrypt"]);
    await s.encrypt({ name: "AES-GCM", iv: buf(new Uint8Array(12)), additionalData: buf(utf8("probe")) }, k, buf(utf8("probe")));
  }, missing);
  await probe("HMAC SHA-256 and SHA-256", async () => {
    const k = await s.importKey("raw", buf(new Uint8Array(32)), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    await s.sign("HMAC", k, buf(utf8("probe")));
    await s.digest("SHA-256", buf(utf8("probe")));
  }, missing);
  await probe("PBKDF2 and AES-KW (the key backup)", async () => {
    const p = await s.importKey("raw", buf(utf8("probe passphrase")), "PBKDF2", false, ["deriveKey"]);
    const kek = await s.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt: buf(new Uint8Array(16)), iterations: 1000 }, p, { name: "AES-KW", length: 128 }, false, ["wrapKey"]);
    const cek = await s.importKey("raw", buf(new Uint8Array(32)), { name: "AES-GCM" }, true, ["encrypt"]);
    await s.wrapKey("raw", cek, kek, "AES-KW");
  }, missing);
  if (typeof (globalThis as Record<string, unknown>).DecompressionStream !== "function" && getInflate() === null) {
    degraded.push("DecompressionStream (status lists read as not checked)");
  }
  return { ok: missing.length === 0, missing, degraded };
}
