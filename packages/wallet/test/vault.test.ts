import { describe, expect, test } from "bun:test";
import { deriveDid } from "@kashscript/identity-core";
import { decodeJws, signJws, verifyJws } from "@kashscript/attest/sd-jwt";
import { MemoryStore } from "../src/adapters/memory-store";
import { newAgreementKeyPair, softwareRoot } from "../src/adapters/software-root";
import { openAead } from "../src/crypto/aead";
import { ed25519PublicKeyOf } from "../src/crypto/ed25519";
import { isWalletError } from "../src/errors";
import { KeyRegistry } from "../src/keys";
import { systemRandom, type HardwareRoot, type RootInfo } from "../src/platform";
import { PREFIX, Vault } from "../src/vault";

const INFO: RootInfo = { strength: "practice", where: "memory", unlock: "none", weaker: true, text: "practice" };

async function fresh() {
  const store = new MemoryStore();
  const root = await softwareRoot(await newAgreementKeyPair(), INFO);
  const vault = await Vault.create(store, root, systemRandom, "Unlock your records");
  return { store, root, vault };
}

/** The vault key, read from the object — the test's own access, not an API. */
const vaultKeyOf = (v: Vault): Uint8Array => (v as unknown as { key: Uint8Array }).key.slice();

describe("the sealed store", () => {
  test("a new vault is open; locked, it reads nothing; the root opens it again", async () => {
    const { vault } = await fresh();
    await vault.put("w.log", { hello: "records" });
    vault.lock();
    expect(isWalletError(await vault.get("w.log").catch((e) => e), "LOCKED")).toBe(true);
    await vault.unlock();
    expect(await vault.get<{ hello: string }>("w.log")).toEqual({ hello: "records" });
  });

  test("another device's root cannot open this vault", async () => {
    const { store } = await fresh();
    const stranger = await softwareRoot(await newAgreementKeyPair(), INFO);
    const other = await Vault.open(store, stranger, systemRandom, "Unlock your records");
    expect(isWalletError(await other.unlock().catch((e) => e), "ROOT_LOST")).toBe(true);
    expect(other.unlocked).toBe(false);
  });

  test("a cancelled prompt leaves the vault locked, and says so", async () => {
    const { store, root } = await fresh();
    const refusing: HardwareRoot = { ...root, agree: async () => { throw new Error("the person cancelled"); } };
    const v = await Vault.open(store, refusing, systemRandom, "Unlock your records");
    await expect(v.unlock()).rejects.toThrow("the person cancelled");
    expect(v.unlocked).toBe(false);
  });

  test("a blob moved to another name does not open", async () => {
    const { store, vault } = await fresh();
    await vault.put(`${PREFIX.ask}aa`, { k: 1 });
    await store.put(`${PREFIX.ask}bb`, (await store.get(`${PREFIX.ask}aa`))!);
    expect(isWalletError(await vault.get(`${PREFIX.ask}bb`).catch((e) => e), "VAULT_CORRUPT")).toBe(true);
  });

  test("deletion is a crypto-shred: a copy of the record taken earlier opens with nothing left", async () => {
    const { store, vault } = await fresh();
    const slot = await vault.newSlot();
    await vault.putRecord(slot, { artifact: "a record that expires" });
    const content = (await store.get(PREFIX.record + slot))!;
    const wrappedKey = (await store.get(PREFIX.recordKey + slot))!;
    const vaultKey = vaultKeyOf(vault);
    // Before: the record's own key (unwrapped by the vault key) opens the copy.
    const recordKey = (await openAead(vaultKey, wrappedKey, PREFIX.recordKey + slot))!;
    expect(await openAead(recordKey, content, PREFIX.record + slot)).not.toBeNull();

    await vault.shredRecord(slot);
    expect(await store.get(PREFIX.recordKey + slot)).toBeNull();
    expect(await store.get(PREFIX.record + slot)).toBeNull();
    // After: the vault key never encrypted the record, and no key for it remains.
    expect(await openAead(vaultKey, content, PREFIX.record + slot)).toBeNull();
    for (const name of await store.list("w.")) {
      if (name === "w.meta") continue;
      const maybeKey = await openAead(vaultKey, (await store.get(name))!, name);
      if (maybeKey !== null && maybeKey.length === 32) expect(await openAead(maybeKey, content, PREFIX.record + slot)).toBeNull();
    }
  });

  test("an interrupted write leaves an orphan that is removed, never trusted", async () => {
    const { store, vault } = await fresh();
    const slot = await vault.newSlot();
    await vault.putRecord(slot, { x: 1 });
    await store.delete(PREFIX.recordKey + slot);
    expect(await vault.recordSlots()).toEqual([]);
    expect(await store.get(PREFIX.record + slot)).toBeNull();
  });
});

describe("the root and the keys", () => {
  test("the root has no way to sign, and its private key cannot be read", async () => {
    const pair = await newAgreementKeyPair();
    const root = await softwareRoot(pair, INFO);
    // @ts-expect-error — a HardwareRoot has no sign method, by design (d47(g)(1)).
    expect(root.sign).toBeUndefined();
    expect(pair.privateKey.extractable).toBe(false);
    expect(pair.privateKey.usages).toEqual(["deriveBits"]);
    await expect(crypto.subtle.exportKey("jwk", pair.privateKey)).rejects.toThrow();
  });

  test("a root that could sign, or be read, is refused", async () => {
    const signing = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])) as CryptoKeyPair;
    await expect(softwareRoot(signing, INFO)).rejects.toThrow();
    const readable = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])) as CryptoKeyPair;
    await expect(softwareRoot(readable, INFO)).rejects.toThrow();
  });

  test("relationship keys sign, are named by their did:kash, and never sit in the store in the clear", async () => {
    const { store, vault, root } = await fresh();
    const keys = new KeyRegistry(vault, root, systemRandom, () => 1_790_000_000);
    const k = await keys.create("relationship");
    let seedSeen: Uint8Array | null = null;
    const jws = await keys.withSigner(k.keyId, async (s) => {
      if (!("privateKey" in s)) throw new Error("a software key carries its seed while it signs");
      seedSeen = s.privateKey.slice();
      expect(String(deriveDid(s.publicKey))).toBe(k.keyId);
      return signJws({ typ: "test" }, { hello: 1 }, s);
    });
    expect(await verifyJws(decodeJws(jws)!, await ed25519PublicKeyOf(seedSeen!))).toBe(true);
    const seedHex = Buffer.from(seedSeen!).toString("hex");
    for (const [, bytes] of (store as MemoryStore).snapshot()) {
      expect(Buffer.from(bytes).toString("hex").includes(seedHex)).toBe(false);
    }
  });

  test("a restored key must match the did:kash it claims", async () => {
    const { vault, root } = await fresh();
    const keys = new KeyRegistry(vault, root, systemRandom, () => 1);
    const seed = new Uint8Array(32).fill(3);
    const pub = await ed25519PublicKeyOf(seed);
    expect((await keys.restore(deriveDid(pub), seed)).purpose).toBe("restored");
    const wrong = await keys.restore(deriveDid(await ed25519PublicKeyOf(new Uint8Array(32).fill(4))), seed).catch((e) => e);
    expect(isWalletError(wrong, "BACKUP_INVALID")).toBe(true);
  });
});
