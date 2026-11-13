import { describe, expect, test } from "bun:test";
import { gzipSync } from "node:zlib";
import { getInflate, setInflate } from "@kashscript/attest/holder";
import { createWebWallet, memoryWebBackend } from "../src/web";
import { checkRuntime, createExpoWallet, expoInflate, type NativeRootModule } from "../src/expo";
import { base64ToBytes, base64UrlToBytes, buf, bytesToBase64, bytesToBase64Url } from "../src/crypto/bytes";
import { ecdsaRawToDer } from "@kashscript/identity-core";
import { isWalletError } from "../src/errors";
import { createHeadlessWallet } from "../src/headless";

/** A stand-in for the native module: WebCrypto where the phone would use its secure chip. */
function fakeNative(opts: { available?: boolean; reason?: "no-screen-lock" | "system-too-old" | "no-secure-hardware" } = {}) {
  let pair: CryptoKeyPair | null = null;
  const blobs = new Map<string, string>();
  const calls = { agree: 0, prompts: [] as string[], signs: 0, signPrompts: [] as string[] };
  const signing = new Map<string, CryptoKeyPair>();
  const native: NativeRootModule = {
    isAvailable: async () => ({ available: opts.available ?? true, reason: opts.reason ?? null }),
    create: async () => {
      if (pair !== null) throw new Error("E_EXISTS");
      pair = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])) as CryptoKeyPair;
      return bytesToBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
    },
    publicKey: async () => (pair === null ? null : bytesToBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)))),
    where: async () => (pair === null ? null : "strongbox"),
    agree: async (_alias, peer, prompt) => {
      calls.agree++;
      calls.prompts.push(prompt);
      const p = await crypto.subtle.importKey("raw", buf(base64UrlToBytes(peer)), { name: "ECDH", namedCurve: "P-256" }, false, []);
      return bytesToBase64Url(new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: p }, pair!.privateKey, 256)));
    },
    remove: async () => {
      const had = pair !== null;
      pair = null;
      return had;
    },
    blobPut: async (name, b64) => {
      blobs.set(name, b64);
    },
    blobGet: async (name) => blobs.get(name) ?? null,
    blobDelete: async (name) => {
      blobs.delete(name);
    },
    blobList: async (prefix) => [...blobs.keys()].filter((n) => n.startsWith(prefix)),
    // Signing keys: separate from the root. Like a real chip, the stand-in answers in DER
    // and does NOT normalise to low-S — the wallet must.
    createSigningKey: async (alias) => {
      const k = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])) as CryptoKeyPair;
      signing.set(alias, k);
      return { publicKey: bytesToBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", k.publicKey))), where: "strongbox" };
    },
    signWithKey: async (alias, message, prompt) => {
      calls.signs++;
      calls.signPrompts.push(prompt);
      const k = signing.get(alias);
      if (k === undefined) throw new Error("E_NO_KEY");
      const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, k.privateKey, buf(base64UrlToBytes(message))));
      return bytesToBase64Url(ecdsaRawToDer(raw));
    },
    removeSigningKey: async (alias) => signing.delete(alias),
  };
  return { native, calls, blobs, signing };
}

describe("the Expo adapter, over a stand-in native module", () => {
  test("the root is labelled hardware; it is asked only to unlock — once — never to sign", async () => {
    const fake = fakeNative();
    const wallet = await createExpoWallet({ native: fake.native, transport: null });
    expect(wallet.root().info).toMatchObject({ strength: "hardware", where: "strongbox", unlock: "biometrics-or-pin", weaker: false });
    expect(fake.calls.agree).toBe(0);
    await wallet.proof.set("https://somewhere.practice.invalid", "on");
    wallet.lock();
    const again = await createExpoWallet({ native: fake.native, transport: null });
    expect(again.unlocked).toBe(false);
    await again.unlock();
    expect(fake.calls.agree).toBe(1);
    expect(fake.calls.prompts).toEqual(["Unlock your records"]);
    expect(await again.proof.get("https://somewhere.practice.invalid")).toBe("on");
    expect(Object.keys(fake.native)).not.toContain("sign");
  });

  test("everything crossing into the native store is ciphertext, except the sealed header", async () => {
    const fake = fakeNative();
    const wallet = await createExpoWallet({ native: fake.native, transport: null });
    await wallet.proof.set("https://somewhere.practice.invalid", "off");
    for (const [name, b64] of fake.blobs) {
      const text = new TextDecoder("utf-8", { fatal: false }).decode(base64ToBytes(b64));
      if (name === "w.meta") expect(JSON.parse(text).format).toBe("kashscript-wallet-vault/1");
      else expect(text.includes('"proof"')).toBe(false);
    }
    expect(bytesToBase64(new Uint8Array([1]))).toBe("AQ==");
  });

  test("no screen lock, or an old system: a plain refusal — never a quieter, weaker key", async () => {
    for (const reason of ["no-screen-lock", "system-too-old", "no-secure-hardware"] as const) {
      const e = await createExpoWallet({ native: fakeNative({ available: false, reason }).native, transport: null }).catch((x) => x);
      expect(isWalletError(e, "ROOT_UNAVAILABLE")).toBe(true);
      expect(e.detail).toContain(reason);
    }
  });

  test("the runtime check passes where WebCrypto is complete, and names what degrades", async () => {
    const r = await checkRuntime();
    expect(r.ok).toBe(true);
    expect(r.missing).toEqual([]);
  });

  test("expoInflate decompresses RFC 1952 gzip data via fflate", () => {
    const orig = new TextEncoder().encode("kashscript status list test bytes");
    const compressed = gzipSync(orig);
    const out = expoInflate(new Uint8Array(compressed));
    expect(out).toEqual(orig);
  });

  test("createExpoWallet sets attest inflate, satisfying checkRuntime without DecompressionStream", async () => {
    setInflate(null);
    const fake = fakeNative();
    await createExpoWallet({ native: fake.native, transport: null });
    expect(getInflate()).toBe(expoInflate);

    const g = globalThis as Record<string, unknown>;
    const saved = g.DecompressionStream;
    try {
      delete g.DecompressionStream;
      const r = await checkRuntime();
      expect(r.degraded).toEqual([]);
    } finally {
      g.DecompressionStream = saved;
    }
  });
});

describe("the web adapter — weaker, and labelled so", () => {
  test("it must be acknowledged as weaker before it opens", async () => {
    const e = await createWebWallet({ acknowledgeWeaker: false as unknown as true, backend: memoryWebBackend(), transport: null }).catch((x) => x);
    expect(isWalletError(e, "WEAKER_NOT_ACKNOWLEDGED")).toBe(true);
  });

  test("its root is a browser key, weaker, in words; it reopens locked and unlocks", async () => {
    const backend = memoryWebBackend();
    const wallet = await createWebWallet({ acknowledgeWeaker: true, backend, transport: null });
    const info = wallet.root().info;
    expect(info).toMatchObject({ strength: "browser", where: "browser", unlock: "none", weaker: true });
    expect(info.text).toContain("phone's secure chip keeps them better");
    await wallet.proof.set("https://portal.practice.invalid", "on");
    const again = await createWebWallet({ acknowledgeWeaker: true, backend, transport: null });
    expect(again.unlocked).toBe(false);
    await again.unlock();
    expect(await again.proof.get("https://portal.practice.invalid")).toBe("on");
    const root = await backend.getRoot();
    expect(root!.privateKey.extractable).toBe(false);
  });
});

describe("the headless mode", () => {
  test("refuses to exist without saying it is practice", async () => {
    const e = await createHeadlessWallet({ practice: false as unknown as true, seed: "x" }).catch((x) => x);
    expect(isWalletError(e, "PRACTICE_ONLY")).toBe(true);
  });

  test("the same seed makes the same relationship keys", async () => {
    const make = async () => {
      const { wallet } = await createHeadlessWallet({ practice: true, seed: "same", now: () => 1_790_337_600 });
      await wallet.proof.set("https://a.practice.invalid", "on");
      return (await wallet.relationships.list()).map((r) => [r.id, r.mailbox]);
    };
    expect(await make()).toEqual(await make());
  });
});
