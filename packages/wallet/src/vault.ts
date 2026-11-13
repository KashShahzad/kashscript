/**
 * The sealed store — everything the wallet keeps, on the holder's own device.
 *
 *   hardware root ──HPKE──▶ vault key ──AES-GCM──▶ relationships, keys, log, lists
 *                                     └─AES-GCM──▶ one key per record ──AES-GCM──▶ the record
 *
 * - The vault key is sealed to the root with HPKE (RFC 9180). Sealing needs
 *   only the root's public key; opening needs the root to agree a key inside
 *   the secure chip — one face, fingerprint or screen-lock prompt per unlock.
 *   `lock()` wipes it from memory.
 * - Every record has its own key, wrapped by the vault key. Deleting a record
 *   deletes that key first, then the ciphertext: a copy of the ciphertext made
 *   earlier can no longer be opened with anything the wallet holds. That is the
 *   crypto-shred of d27.5 — deletion at expiry that is real. Honest limit:
 *   flash storage may keep remnants of deleted files, so against someone who
 *   images the chip AND can unlock this phone's root, deletion is only as good
 *   as the platform's own secure deletion.
 * - Names are random slot ids, never record ids or identifiers, so the store
 *   cannot be asked "do you hold X?". Associated data binds each blob to its
 *   name, so a blob moved elsewhere fails to open.
 * - The only plain blob is the header: the sealed vault key.
 */

import { openAead, sealAead } from "./crypto/aead";
import { base64UrlToBytes, bytesToBase64Url, bytesToHex, utf8, utf8Decode, wipe } from "./crypto/bytes";
import { hpkeOpen, hpkeSeal } from "./crypto/hpke";
import { WalletError } from "./errors";
import type { BlobStore, HardwareRoot, Random } from "./platform";

export const VAULT_FORMAT = "kashscript-wallet-vault/1" as const;
const META = "w.meta";
const VAULT_INFO = utf8(VAULT_FORMAT);

/** Store prefixes. Records are two blobs: their key (`w.d.`) and their content (`w.c.`). */
export const PREFIX = {
  key: "w.k.",
  seed: "w.ks.",
  /** PL-2: the opaque handle of a key held in hardware — never the key itself. */
  handle: "w.kh.",
  /** PL-2: people this wallet helps — their circle and the helper keys held for them. */
  helping: "w.rh.",
  /** PL-2: key-succession claims this holder made or received. */
  succession: "w.rs.",
  relationship: "w.r.",
  recordKey: "w.d.",
  record: "w.c.",
  trustList: "w.t.",
  statusList: "w.s.",
  ask: "w.a.",
  heldKey: "w.h.",
  revocation: "w.v.",
} as const;
export const LOG = "w.log";
/** PL-2: the holder's own helpers, need and per-place helper sets. */
export const RECOVERY = "w.rc";
/** PL-2: a recovery in progress on a new phone. */
export const RECOVERY_PENDING = "w.rp";

interface Meta {
  readonly format: typeof VAULT_FORMAT;
  readonly sealed: { readonly enc: string; readonly ct: string };
}

function isMeta(v: unknown): v is Meta {
  if (typeof v !== "object" || v === null) return false;
  const m = v as Record<string, unknown>;
  const s = m.sealed as Record<string, unknown> | undefined;
  return m.format === VAULT_FORMAT && typeof s === "object" && s !== null && typeof s.enc === "string" && typeof s.ct === "string";
}

export class Vault {
  private key: Uint8Array | null;

  private constructor(
    private readonly store: BlobStore,
    private readonly root: HardwareRoot,
    private readonly random: Random,
    private readonly prompt: string,
    key: Uint8Array | null,
  ) {
    this.key = key;
  }

  static async exists(store: BlobStore): Promise<boolean> {
    return (await store.get(META)) !== null;
  }

  /** First run: a fresh vault key, sealed to the root. Returned unlocked. */
  static async create(store: BlobStore, root: HardwareRoot, random: Random, prompt: string): Promise<Vault> {
    const key = await random(32);
    const sealed = await hpkeSeal(root.publicKey(), VAULT_INFO, utf8(META), key);
    const meta: Meta = { format: VAULT_FORMAT, sealed: { enc: bytesToBase64Url(sealed.enc), ct: bytesToBase64Url(sealed.ct) } };
    await store.put(META, utf8(JSON.stringify(meta)));
    return new Vault(store, root, random, prompt, key);
  }

  /** An existing vault, locked. */
  static async open(store: BlobStore, root: HardwareRoot, random: Random, prompt: string): Promise<Vault> {
    return new Vault(store, root, random, prompt, null);
  }

  get unlocked(): boolean {
    return this.key !== null;
  }

  /** Asks the root — and so the person — once. A cancelled prompt throws and leaves it locked. */
  async unlock(): Promise<void> {
    if (this.key !== null) return;
    const raw = await this.store.get(META);
    let meta: unknown = null;
    try {
      meta = raw === null ? null : JSON.parse(utf8Decode(raw) ?? "");
    } catch {
      meta = null;
    }
    if (!isMeta(meta)) throw new WalletError("VAULT_CORRUPT", "the vault header is missing or malformed");
    const key = await hpkeOpen(
      { enc: base64UrlToBytes(meta.sealed.enc), ct: base64UrlToBytes(meta.sealed.ct) },
      this.root.publicKey(),
      VAULT_INFO,
      utf8(META),
      (enc) => this.root.agree(enc, this.prompt),
    );
    if (key === null || key.length !== 32) throw new WalletError("ROOT_LOST", "the root on this device does not open this vault");
    this.key = key;
  }

  lock(): void {
    wipe(this.key);
    this.key = null;
  }

  private need(): Uint8Array {
    if (this.key === null) throw new WalletError("LOCKED");
    return this.key;
  }

  async newSlot(): Promise<string> {
    return bytesToHex(await this.random(16));
  }

  /* ── values under the vault key ──────────────────────────────────────── */

  async putBytes(name: string, bytes: Uint8Array): Promise<void> {
    await this.store.put(name, await sealAead(this.need(), bytes, name, this.random));
  }

  async getBytes(name: string): Promise<Uint8Array | null> {
    const key = this.need();
    const sealed = await this.store.get(name);
    if (sealed === null) return null;
    const plain = await openAead(key, sealed, name);
    if (plain === null) throw new WalletError("VAULT_CORRUPT", `${name} does not open`);
    return plain;
  }

  async put(name: string, value: unknown): Promise<void> {
    await this.putBytes(name, utf8(JSON.stringify(value)));
  }

  async get<T>(name: string): Promise<T | null> {
    const bytes = await this.getBytes(name);
    if (bytes === null) return null;
    const text = utf8Decode(bytes);
    wipe(bytes);
    return text === null ? null : (JSON.parse(text) as T);
  }

  async remove(name: string): Promise<void> {
    await this.store.delete(name);
  }

  async names(prefix: string): Promise<readonly string[]> {
    return [...(await this.store.list(prefix))].sort();
  }

  async all<T>(prefix: string): Promise<{ name: string; value: T }[]> {
    const out: { name: string; value: T }[] = [];
    for (const name of await this.names(prefix)) {
      const value = await this.get<T>(name);
      if (value !== null) out.push({ name, value });
    }
    return out;
  }

  /* ── records: each under its own key ─────────────────────────────────── */

  async putRecord(slot: string, value: unknown): Promise<void> {
    const recordKey = await this.random(32);
    try {
      const contentName = PREFIX.record + slot;
      // Content first, then its key: a crash between leaves an orphan the sweep removes.
      await this.store.put(contentName, await sealAead(recordKey, utf8(JSON.stringify(value)), contentName, this.random));
      await this.putBytes(PREFIX.recordKey + slot, recordKey);
    } finally {
      wipe(recordKey);
    }
  }

  async getRecord<T>(slot: string): Promise<T | null> {
    const recordKey = await this.getBytes(PREFIX.recordKey + slot);
    if (recordKey === null) return null;
    try {
      const contentName = PREFIX.record + slot;
      const sealed = await this.store.get(contentName);
      if (sealed === null) return null;
      const plain = await openAead(recordKey, sealed, contentName);
      if (plain === null) throw new WalletError("VAULT_CORRUPT", `${contentName} does not open`);
      const text = utf8Decode(plain);
      wipe(plain);
      return text === null ? null : (JSON.parse(text) as T);
    } finally {
      wipe(recordKey);
    }
  }

  /** The crypto-shred: the record's own key goes first, then its ciphertext. */
  async shredRecord(slot: string): Promise<void> {
    await this.store.delete(PREFIX.recordKey + slot);
    await this.store.delete(PREFIX.record + slot);
  }

  async recordSlots(): Promise<readonly string[]> {
    const keys = new Set((await this.names(PREFIX.recordKey)).map((n) => n.slice(PREFIX.recordKey.length)));
    const contents = (await this.names(PREFIX.record)).map((n) => n.slice(PREFIX.record.length));
    // An orphan on either side (an interrupted write) is removed rather than trusted.
    for (const slot of contents) if (!keys.has(slot)) await this.store.delete(PREFIX.record + slot);
    const withContent = new Set(contents);
    for (const slot of keys) if (!withContent.has(slot)) await this.store.delete(PREFIX.recordKey + slot);
    return contents.filter((s) => keys.has(s)).sort();
  }
}
