/**
 * The ports an adapter fills. The core is headless TypeScript: it never
 * touches a keychain, a file, a clock or the network except through these.
 *
 *   root       the hardware root key (P-256). It AGREES keys and nothing else.
 *              There is no sign method, so no code path can make it sign a
 *              record (d47(g)(1): "it signs no records and guards everything else").
 *   store      opaque names → opaque bytes. The core only ever writes ciphertext,
 *              except the one sealed-vault header.
 *   random     a cryptographic random source (a seeded one only in headless mode).
 *   now        unix seconds — injected, so expiry is tested with a clock, never by editing data.
 *   transport  the only way out. Null means the wallet never sends anything.
 */

export type RootStrength = "hardware" | "browser" | "practice";
export type RootWhere = "secure-enclave" | "strongbox" | "trusted-environment" | "browser" | "memory";

export interface RootInfo {
  readonly strength: RootStrength;
  readonly where: RootWhere;
  /** How the root is unlocked. `none` means anyone using the device can use it. */
  readonly unlock: "biometrics-or-pin" | "none";
  /** True for anything weaker than a phone's secure chip. Surfaces must say so. */
  readonly weaker: boolean;
  /** Plain words a surface shows. */
  readonly text: string;
}

/**
 * The hardware root. It seals and unseals; it cannot sign. Its public key is a
 * stable identifier for the device, so it never leaves the device — it is in
 * no export, and the transport refuses to send it.
 */
export interface HardwareRoot {
  info(): RootInfo;
  /** Uncompressed SEC1 P-256 public key, 65 bytes (0x04 ‖ X ‖ Y). */
  publicKey(): Uint8Array;
  /**
   * ECDH between the root's private key and `peerPublicKey` (65-byte SEC1),
   * returning the 32-byte shared secret. On a phone this asks for the face,
   * fingerprint or screen lock, showing `prompt`.
   */
  agree(peerPublicKey: Uint8Array, prompt: string): Promise<Uint8Array>;
}

export interface RootProvider {
  /** The existing root, or null on first run. */
  open(): Promise<HardwareRoot | null>;
  /** Make the root. Keys first: no account, no server, nothing sent. */
  create(): Promise<HardwareRoot>;
}

/** Names are `[a-z0-9.]` only, so every adapter can use them as file names. */
export interface BlobStore {
  put(name: string, bytes: Uint8Array): Promise<void>;
  get(name: string): Promise<Uint8Array | null>;
  delete(name: string): Promise<void>;
  list(prefix: string): Promise<readonly string[]>;
}

export type Random = (length: number) => Promise<Uint8Array>;
export type Clock = () => number;

export interface HttpRequest {
  readonly url: string;
  readonly method: "GET" | "POST";
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string | null;
}

export interface HttpResponse {
  readonly status: number;
  readonly text: string;
}

export type Transport = (request: HttpRequest) => Promise<HttpResponse>;

/**
 * Signing keys that live in the hardware (PL-2, d47(g)(2): "they sign in
 * hardware where the hardware holds the algorithm"). A phone's secure chip
 * holds P-256, so these are ES256 keys — one per place, one per copy of a yes —
 * made in the chip and never leaving it. They are NOT the root: the root still
 * only agrees keys and cannot sign. A key here is named by an opaque handle the
 * vault keeps sealed; its private half never reaches JavaScript.
 */
export interface HardwareSigners {
  info(): { readonly strength: RootStrength; readonly where: RootWhere; readonly text: string };
  /** Make a P-256 signing key. Returns its handle and its public key (65-byte SEC1). */
  create(): Promise<{ readonly handle: string; readonly publicKey: Uint8Array }>;
  /**
   * ES256 over exactly `message` — the hardware hashes it with SHA-256 — after
   * the face, fingerprint or screen lock, showing `prompt`. Returns ASN.1 DER,
   * as the chips do; the wallet normalises it to low-S.
   */
  sign(handle: string, message: Uint8Array, prompt: string): Promise<Uint8Array>;
  remove(handle: string): Promise<void>;
}

export interface WalletPlatform {
  readonly roots: RootProvider;
  readonly store: BlobStore;
  readonly random: Random;
  readonly now: Clock;
  readonly transport: Transport | null;
  /** Hardware signing keys. Absent: relationship keys are Ed25519, sealed by the root, as before PL-2. */
  readonly signers?: HardwareSigners | null;
}

/** The platform's random source over `crypto.getRandomValues`. */
export const systemRandom: Random = async (length) => crypto.getRandomValues(new Uint8Array(length));

export const systemClock: Clock = () => Math.floor(Date.now() / 1000);
