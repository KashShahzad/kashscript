/**
 * The key registry: a reference to the hardware root, plus the keys the
 * holder signs with.
 *
 * - **The root** is referenced, never held: the registry exposes what it is
 *   (secure chip, browser, practice) and nothing that identifies it. It never
 *   signs (d47(g)(1)).
 * - **Relationship keys** — one per place (d41: separate identifiers per
 *   relationship; d47(g)(2)). **Where the hardware holds the algorithm, they
 *   sign in it:** with a `signers` port (a phone's secure chip) they are P-256
 *   keys made in the chip, signing ES256, and only an opaque handle — sealed in
 *   the vault — ever reaches JavaScript (PL-2). Otherwise they are Ed25519 seeds
 *   from the platform's random source, sealed under the vault key, opened only
 *   to sign and wiped straight after. Hardware can't derive keys, so every key
 *   is generated for its place and recorded here (identity-server's HKDF path
 *   is for server-side ceremonies only).
 * - **Copy keys** — one per issued copy of a yes (presentation §4), so no two
 *   verifiers ever see the same key. Made like relationship keys.
 * - **Helper keys** — keys this wallet holds as someone else's helper
 *   (specs/recovery.md): sealed Ed25519, a pool per person helped, one key per
 *   place of theirs, so a helper key never links two of their places.
 * - **Restored keys** — brought back from a backup the holder asked for.
 *
 * A seed leaves the device only inside a backup the holder asked for. **A key
 * held in hardware never leaves at all** — after a lost phone it is succeeded,
 * never copied (d47(g)(4)).
 */

import { compressP256PublicKey, deriveDid, deriveDidP256, isKashDid, type EventSigner } from "@kashscript/identity-core";
import type { RawSigner } from "@kashscript/attest/signing";
import type { BackedUpKey } from "./crypto/jwe";
import { bytesToBase64Url, bytesToHex, base64UrlToBytes, equalBytes, hexToBytes, utf8, utf8Decode, wipe } from "./crypto/bytes";
import { ed25519PublicKeyOf } from "./crypto/ed25519";
import { WalletError } from "./errors";
import type { Clock, HardwareRoot, HardwareSigners, Random, RootInfo } from "./platform";
import { PREFIX, type Vault } from "./vault";

export type KeyPurpose = "relationship" | "copy" | "restored" | "helper";

export interface KeyEntry {
  readonly slot: string;
  /** The key's name — its `did:kash` for every key made here; a restored key keeps the id it came with. */
  readonly keyId: string;
  readonly alg: "EdDSA" | "ES256";
  /** `hardware`: made in, and signing in, the secure chip. `sealed-software`: a seed sealed by the root. */
  readonly custody: "sealed-software" | "hardware";
  readonly purpose: KeyPurpose;
  /** Base64url: 32 bytes for Ed25519, the 33-byte compressed point for P-256. */
  readonly publicKey: string;
  readonly createdAtUnix: number;
}

/** What attest's signing functions take — DSSE (`keyid`), JWS, sessions — with the key's DID. */
export type WalletSigner = RawSigner & { readonly keyid: string; readonly did: string };

/** What identity-core's Kash-Event signing takes (key claims, helper sets), with the key's DID. */
export type WalletEventSigner = EventSigner & { readonly did: string };

/** What the registry says about the root: what it is, never who it is. */
export interface RootReference {
  readonly info: RootInfo;
}

export class KeyRegistry {
  constructor(
    private readonly vault: Vault,
    private readonly rootRef: HardwareRoot,
    private readonly random: Random,
    private readonly now: Clock,
    private readonly signers: HardwareSigners | null = null,
    private readonly signPrompt: string = "Sign",
  ) {}

  root(): RootReference {
    return { info: this.rootRef.info() };
  }

  /** Where signing keys live: in the hardware (`ES256`), or sealed in software (`EdDSA`). */
  signing(): { readonly alg: "ES256" | "EdDSA"; readonly where: string } {
    return this.signers === null ? { alg: "EdDSA", where: "sealed by the root" } : { alg: "ES256", where: this.signers.info().where };
  }

  async create(purpose: Exclude<KeyPurpose, "restored">): Promise<KeyEntry> {
    if (this.signers !== null && purpose !== "helper") return this.createInHardware(purpose);
    const seed = await this.random(32);
    try {
      const publicKey = await ed25519PublicKeyOf(seed);
      return await this.store(deriveDid(publicKey), seed, publicKey, purpose);
    } finally {
      wipe(seed);
    }
  }

  private async createInHardware(purpose: Exclude<KeyPurpose, "restored" | "helper">): Promise<KeyEntry> {
    const made = await (this.signers as HardwareSigners).create();
    const publicKey = compressP256PublicKey(made.publicKey);
    const slot = await this.vault.newSlot();
    const entry: KeyEntry = {
      slot,
      keyId: deriveDidP256(publicKey),
      alg: "ES256",
      custody: "hardware",
      purpose,
      publicKey: bytesToBase64Url(publicKey),
      createdAtUnix: this.now(),
    };
    await this.vault.putBytes(PREFIX.handle + slot, utf8(made.handle));
    await this.vault.put(PREFIX.key + slot, entry);
    return entry;
  }

  /** Bring a key back from a backup. A `did:kash` id must name the key it came with. */
  async restore(keyid: string, seed: Uint8Array): Promise<KeyEntry> {
    const publicKey = await ed25519PublicKeyOf(seed);
    if (isKashDid(keyid) && deriveDid(publicKey) !== keyid) {
      throw new WalletError("BACKUP_INVALID", `key ${keyid} does not match its seed`);
    }
    const existing = await this.find(keyid);
    if (existing !== null) return existing;
    return this.store(keyid, seed, publicKey, "restored");
  }

  private async store(keyId: string, seed: Uint8Array, publicKey: Uint8Array, purpose: KeyPurpose): Promise<KeyEntry> {
    const slot = await this.vault.newSlot();
    const entry: KeyEntry = {
      slot,
      keyId,
      alg: "EdDSA",
      custody: "sealed-software",
      purpose,
      publicKey: bytesToBase64Url(publicKey),
      createdAtUnix: this.now(),
    };
    await this.vault.putBytes(PREFIX.seed + slot, seed);
    await this.vault.put(PREFIX.key + slot, entry);
    return entry;
  }

  async list(): Promise<readonly KeyEntry[]> {
    return (await this.vault.all<KeyEntry>(PREFIX.key)).map((e) => e.value);
  }

  async find(keyId: string): Promise<KeyEntry | null> {
    return (await this.list()).find((k) => k.keyId === keyId) ?? null;
  }

  async remove(keyId: string): Promise<void> {
    const k = await this.find(keyId);
    if (k === null) return;
    if (k.custody === "hardware") {
      const handle = await this.vault.getBytes(PREFIX.handle + k.slot);
      if (handle !== null && this.signers !== null) await this.signers.remove(utf8Decode(handle) ?? "");
      await this.vault.remove(PREFIX.handle + k.slot);
    }
    await this.vault.remove(PREFIX.seed + k.slot);
    await this.vault.remove(PREFIX.key + k.slot);
  }

  private async hardwareSign(k: KeyEntry): Promise<(message: Uint8Array) => Promise<Uint8Array>> {
    const handleBytes = await this.vault.getBytes(PREFIX.handle + k.slot);
    if (handleBytes === null || this.signers === null) throw new WalletError("VAULT_CORRUPT", `the hardware key ${k.keyId} is not on this device`);
    const handle = utf8Decode(handleBytes) ?? "";
    const signers = this.signers;
    return (message) => signers.sign(handle, message, this.signPrompt);
  }

  /** Open a key only for as long as `use` runs, then wipe it. A hardware key is never opened: it signs in the chip. */
  async withSigner<T>(keyId: string, use: (signer: WalletSigner) => Promise<T>): Promise<T> {
    const k = await this.find(keyId);
    if (k === null) throw new WalletError("NOT_FOUND", `no key ${keyId}`);
    if (k.custody === "hardware") {
      const sign = await this.hardwareSign(k);
      return use({ alg: "ES256", keyid: k.keyId, did: k.keyId, publicKey: base64UrlToBytes(k.publicKey), sign: async (m) => ({ signature: await sign(m), format: "der" }) });
    }
    return this.withSeed(k, (seed, publicKey) => use({ keyid: k.keyId, did: k.keyId, privateKey: seed, publicKey }));
  }

  /** The same key, as a Kash-Event signer — for key claims and helper sets. */
  async withEventSigner<T>(keyId: string, use: (signer: WalletEventSigner) => Promise<T>): Promise<T> {
    const k = await this.find(keyId);
    if (k === null) throw new WalletError("NOT_FOUND", `no key ${keyId}`);
    if (k.custody === "hardware") {
      const sign = await this.hardwareSign(k);
      return use({ alg: "es256", did: k.keyId, sign: async (m) => ({ signature: await sign(m), format: "der" }) });
    }
    return this.withSeed(k, (seed) => use({ alg: "ed25519", did: k.keyId, privateKey: seed }));
  }

  private async withSeed<T>(k: KeyEntry, use: (seed: Uint8Array, publicKey: Uint8Array) => Promise<T>): Promise<T> {
    const seed = await this.vault.getBytes(PREFIX.seed + k.slot);
    if (seed === null) throw new WalletError("VAULT_CORRUPT", `the seed for ${k.keyId} is missing`);
    try {
      const publicKey = base64UrlToBytes(k.publicKey);
      if (!equalBytes(await ed25519PublicKeyOf(seed), publicKey)) throw new WalletError("VAULT_CORRUPT", `the seed for ${k.keyId} does not match`);
      return await use(seed, publicKey);
    } finally {
      wipe(seed);
    }
  }

  /** Every key that CAN leave, for a backup the holder asked for. Keys in the hardware never can. */
  async backupEntries(): Promise<BackedUpKey[]> {
    const out: BackedUpKey[] = [];
    for (const k of await this.list()) {
      if (k.custody === "hardware") continue;
      const seed = await this.vault.getBytes(PREFIX.seed + k.slot);
      if (seed === null) continue;
      out.push({ keyid: k.keyId, alg: "Ed25519", privateKeyHex: bytesToHex(seed) });
      wipe(seed);
    }
    return out;
  }

  /** How many keys live in the hardware — none of them can be in a backup. */
  async hardwareKeyCount(): Promise<number> {
    return (await this.list()).filter((k) => k.custody === "hardware").length;
  }

  /** Restore every key in a decrypted backup. */
  async restoreAll(keys: readonly BackedUpKey[]): Promise<number> {
    let n = 0;
    for (const k of keys) {
      const seed = hexToBytes(k.privateKeyHex);
      try {
        await this.restore(k.keyid, seed);
        n++;
      } finally {
        wipe(seed);
      }
    }
    return n;
  }
}
