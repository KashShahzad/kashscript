/**
 * PL-2 in the wallet: keys that sign in the secure chip (ES256), and recovery
 * by helpers — the rules the holder's choice must keep, the per-place helper
 * keys, what a backup can and cannot carry. The full lost-phone run is the
 * headless `recover` scenario (test/headless.test.ts).
 */

import { describe, expect, test } from "bun:test";
import { decompressP256PublicKey, didKeyType, ecdsaRawToDer, parseDidKey } from "@kashscript/identity-core";
import { verifyHelperSet, type SignedHelperSet } from "@kashscript/attest/succession";
import { createExpoWallet, type NativeRootModule } from "../src/expo";
import { createHeadlessWallet } from "../src/headless";
import { base64UrlToBytes, buf, bytesToBase64Url } from "../src/crypto/bytes";
import { keyEncodings } from "../src/core";
import { isWalletError } from "../src/errors";
import type { HelperEnrolment } from "../src/recovery";

/** The adapter test's stand-in, trimmed: a root that only agrees, and signing keys answering in raw DER. */
function chip() {
  let root: CryptoKeyPair | null = null;
  const blobs = new Map<string, string>();
  const signing = new Map<string, CryptoKeyPair>();
  const calls = { signs: 0, prompts: [] as string[] };
  const native: NativeRootModule = {
    isAvailable: async () => ({ available: true, reason: null }),
    create: async () => {
      root = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])) as CryptoKeyPair;
      return bytesToBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", root.publicKey)));
    },
    publicKey: async () => (root === null ? null : bytesToBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", root.publicKey)))),
    where: async () => (root === null ? null : "secure-enclave"),
    agree: async (_a, peer) => {
      const p = await crypto.subtle.importKey("raw", buf(base64UrlToBytes(peer)), { name: "ECDH", namedCurve: "P-256" }, false, []);
      return bytesToBase64Url(new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: p }, root!.privateKey, 256)));
    },
    remove: async () => true,
    blobPut: async (n, b) => void blobs.set(n, b),
    blobGet: async (n) => blobs.get(n) ?? null,
    blobDelete: async (n) => void blobs.delete(n),
    blobList: async (prefix) => [...blobs.keys()].filter((n) => n.startsWith(prefix)),
    createSigningKey: async (alias) => {
      const k = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])) as CryptoKeyPair;
      signing.set(alias, k);
      return { publicKey: bytesToBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", k.publicKey))), where: "secure-enclave" };
    },
    signWithKey: async (alias, message, prompt) => {
      calls.signs++;
      calls.prompts.push(prompt);
      const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signing.get(alias)!.privateKey, buf(base64UrlToBytes(message))));
      return bytesToBase64Url(ecdsaRawToDer(raw)); // as a chip does: DER, and NOT normalised to low-S
    },
    removeSigningKey: async (alias) => signing.delete(alias),
  };
  return { native, calls, blobs, signing };
}

async function helpersFor(invite: Parameters<Awaited<ReturnType<typeof createHeadlessWallet>>["wallet"]["recovery"]["becomeHelper"]>[0], n: number, tag: string) {
  const out: { label: string; enrolment: HelperEnrolment }[] = [];
  for (let i = 0; i < n; i++) {
    const h = await createHeadlessWallet({ practice: true, seed: `${tag}/helper-${i}`, transport: null });
    out.push({ label: `helper ${i}`, enrolment: await h.wallet.recovery.becomeHelper(invite, "someone I help") });
  }
  return out;
}

const code = async (run: () => Promise<unknown>): Promise<string> => {
  try {
    await run();
    return "accepted";
  } catch (e) {
    return isWalletError(e) ? e.code : String(e);
  }
};

describe("keys in the secure chip — ES256, and the root still never signs", () => {
  test("a place's key is made in the chip, signs there after the unlock prompt, and every signature is low-S", async () => {
    const c = chip();
    const wallet = await createExpoWallet({ native: c.native, transport: null });
    const places = ["https://a.practice.invalid", "https://b.practice.invalid", "https://c.practice.invalid", "https://d.practice.invalid", "https://e.practice.invalid", "https://f.practice.invalid"];
    for (const p of places) {
      await wallet.proof.set(p, "on");
      const j = await wallet.sessions.join(p);
      expect(j.status === "joined" && didKeyType(j.personDid)).toBe("P-256");
    }
    expect(c.signing.size).toBe(6);
    const helpers = await helpersFor(await wallet.recovery.invite(), 3, "chip");
    await wallet.recovery.chooseHelpers(helpers, 2);
    // six helper sets, each signed in the chip: the stand-in returns raw high-S about half the time,
    // so all six verifying (the verifier rejects high-S) shows the wallet normalised every one.
    expect(c.calls.signs).toBe(6);
    expect(new Set(c.calls.prompts)).toEqual(new Set(["Sign with your key for this place"]));
    const exported = JSON.parse((await wallet.exportAll()).text) as { recoveryHelpers: { helperSet: SignedHelperSet }[] };
    for (const e of exported.recoveryHelpers) {
      expect(didKeyType(e.helperSet.body.subjectDid)).toBe("P-256");
      expect((await verifyHelperSet(e.helperSet)).ok).toBe(true);
    }
  });

  test("a key in the chip never enters a backup — the person is told how many could not", async () => {
    const c = chip();
    const wallet = await createExpoWallet({ native: c.native, transport: null });
    await wallet.proof.set("https://a.practice.invalid", "on");
    await wallet.sessions.join("https://a.practice.invalid");
    const withKeys = await wallet.exportAll({ passphrase: "practice passphrase" });
    expect(withKeys.keysInChip).toBe(1);
    expect(wallet.copy().backupChipKeys).toContain("{n} of your keys stay in this phone's secure chip");
    const elsewhere = await createHeadlessWallet({ practice: true, seed: "chip/elsewhere", transport: null });
    expect((await elsewhere.wallet.importAll(withKeys.text, { passphrase: "practice passphrase" })).keysRestored).toBe(0);
    // nothing in the native store holds a private key: the store holds only sealed handles
    for (const [, b64] of c.blobs) expect(Buffer.from(b64, "base64").toString("latin1").includes("BEGIN")).toBe(false);
  });
});

describe("choosing helpers — what the wallet refuses, and why", () => {
  test("an answer to another person's invitation, a shared key, and a non-majority are refused", async () => {
    const me = await createHeadlessWallet({ practice: true, seed: "rules/me", transport: null });
    const other = await createHeadlessWallet({ practice: true, seed: "rules/other", transport: null });
    const four = await helpersFor(await me.wallet.recovery.invite(), 4, "rules");
    const foreign = await helpersFor(await other.wallet.recovery.invite(), 1, "rules-foreign");
    expect(await code(() => me.wallet.recovery.chooseHelpers([...four.slice(0, 2), foreign[0]!], 2))).toBe("RECOVERY_HELPERS_INVALID");
    const shared = { label: "copycat", enrolment: { ...four[1]!.enrolment } };
    expect(await code(() => me.wallet.recovery.chooseHelpers([four[0]!, four[1]!, shared], 2))).toBe("RECOVERY_HELPERS_INVALID");
    expect(await code(() => me.wallet.recovery.chooseHelpers(four, 2))).toBe("RECOVERY_HELPERS_INVALID"); // 2 of 4 is not a majority
    expect(await code(() => me.wallet.recovery.chooseHelpers(four, 3))).toBe("accepted"); // 3 of 4 is
    expect((await me.wallet.recovery.status()).need).toBe(3);
  });

  test("a helper key is never reused: when a pool runs out, a place waits uncovered", async () => {
    const me = await createHeadlessWallet({ practice: true, seed: "pool/me", transport: null });
    const invite = await me.wallet.recovery.invite();
    const full = await helpersFor(invite, 3, "pool");
    const tiny = full.map((h) => ({ label: h.label, enrolment: { ...h.enrolment, keys: h.enrolment.keys.slice(0, 1) } }));
    await me.wallet.recovery.chooseHelpers(tiny, 2);
    for (const p of ["https://a.practice.invalid", "https://b.practice.invalid"]) {
      await me.wallet.proof.set(p, "on");
      await me.wallet.sessions.join(p);
    }
    const s = await me.wallet.recovery.status();
    expect([s.covered, s.uncovered, s.placesLeft]).toEqual([1, 1, 0]);
    expect(s.text).toContain("aren't covered yet");
  });
});

describe("the request and its approvals", () => {
  test("an approval for some other claim changes nothing", async () => {
    const old = await createHeadlessWallet({ practice: true, seed: "stray/old", transport: null });
    await old.wallet.proof.set("https://a.practice.invalid", "on");
    await old.wallet.sessions.join("https://a.practice.invalid");
    const helpers = await helpersFor(await old.wallet.recovery.invite(), 3, "stray");
    await old.wallet.recovery.chooseHelpers(helpers, 2);
    const saved = (await old.wallet.exportAll()).text;
    const fresh = await createHeadlessWallet({ practice: true, seed: "stray/new", transport: null, hardwareSigning: true });
    const { request } = await fresh.wallet.recovery.startOnNewPhone(saved);
    expect(request.claims.length).toBe(1);
    const stray = { format: "kashscript-recovery-approval/1" as const, approvals: [{ claimSha256: "0".repeat(64), did: helpers[0]!.enrolment.keys[0]!, signature: request.claims[0]!.signatures.successor }], enrolment: helpers[0]!.enrolment };
    const r = await fresh.wallet.recovery.finish([{ label: "x", approval: stray }, { label: "y", approval: stray }]);
    expect(r.status).toBe("waiting");
    expect((await fresh.wallet.relationships.list()).length).toBe(0);
  });

  test("a file saved before any helpers were chosen has nothing for helpers to bring back", async () => {
    const old = await createHeadlessWallet({ practice: true, seed: "nohelpers/old", transport: null });
    const fresh = await createHeadlessWallet({ practice: true, seed: "nohelpers/new", transport: null });
    expect(await code(async () => fresh.wallet.recovery.startOnNewPhone((await old.wallet.exportAll()).text))).toBe("RECOVERY_NOTHING_TO_RECOVER");
  });
});

describe("the outbound guard knows a P-256 key in every form it travels in", () => {
  test("its DID, its body, its compressed point and its JWK x and y", async () => {
    const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"])) as CryptoKeyPair;
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
    const compressed = new Uint8Array(33);
    compressed[0] = (raw[64]! & 1) === 1 ? 0x03 : 0x02;
    compressed.set(raw.subarray(1, 33), 1);
    const { deriveDidP256 } = await import("@kashscript/identity-core");
    const did = deriveDidP256(compressed);
    const forms = keyEncodings(did, bytesToBase64Url(compressed));
    const jwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as JsonWebKey;
    expect(forms).toContain(jwk.x!);
    expect(forms).toContain(jwk.y!);
    expect(forms).toContain(did.slice("did:kash:".length));
    expect(Buffer.from(decompressP256PublicKey(parseDidKey(did).publicKey)).equals(Buffer.from(raw))).toBe(true);
  });
});
