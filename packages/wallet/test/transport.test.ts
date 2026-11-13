import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { guardedSend } from "../src/transport";
import { isWalletError } from "../src/errors";
import { bytesToBase64Url, utf8 } from "../src/crypto/bytes";
import type { HttpRequest, Transport } from "../src/platform";

const MINE = "did:kash:7Vh3S9mYvNqZr2pXcL8tQwEe4uJkB6aDf1gHnR5sTyUo";
const OTHER = "did:kash:3KxqWm9ZtR7yPv2LcN8eHs5dGf4bJaQ6uVwXr1TzEoMi";
const ROOT = "BOx8m2kd9Qvt3LrZ7pYwN4cHs6aJf1gUeXb5nTzR0yWoq8V";

const ids = { all: [MINE, OTHER, ROOT] };
const post = (body: string, url = "https://issuer.practice.invalid/credential"): HttpRequest => ({ url, method: "POST", headers: { "content-type": "application/json" }, body });

function counting(): { transport: Transport; calls: () => number } {
  let n = 0;
  return {
    transport: async () => {
      n++;
      return { status: 200, text: "{}" };
    },
    calls: () => n,
  };
}

describe("the outbound guard", () => {
  test("a request carrying only its own relationship's key goes", async () => {
    const t = counting();
    await guardedSend(t.transport, post(JSON.stringify({ kid: MINE })), ids, [MINE]);
    expect(t.calls()).toBe(1);
  });

  test("another relationship's key — or the root — stops it before sending", async () => {
    for (const leak of [OTHER, ROOT]) {
      const t = counting();
      const e = await guardedSend(t.transport, post(JSON.stringify({ kid: MINE, extra: leak })), ids, [MINE]).catch((x) => x);
      expect(isWalletError(e, "IDENTIFIER_LEAK")).toBe(true);
      expect(t.calls()).toBe(0);
    }
  });

  test("it reads inside JWTs and form fields, not just the raw text", async () => {
    const hidden = `${bytesToBase64Url(utf8(JSON.stringify({ alg: "EdDSA" })))}.${bytesToBase64Url(utf8(JSON.stringify({ kid: OTHER })))}.sig`;
    const t = counting();
    const inJwt = await guardedSend(t.transport, post(JSON.stringify({ proofs: { jwt: [hidden] } })), ids, [MINE]).catch((x) => x);
    expect(isWalletError(inJwt, "IDENTIFIER_LEAK")).toBe(true);
    const form: HttpRequest = { url: "https://v.practice.invalid/response", method: "POST", headers: {}, body: new URLSearchParams({ vp_token: JSON.stringify({ n1: [OTHER] }) }).toString() };
    expect(isWalletError(await guardedSend(t.transport, form, ids, [MINE]).catch((x) => x), "IDENTIFIER_LEAK")).toBe(true);
    expect(t.calls()).toBe(0);
  });

  test("not https, or no transport: nothing is sent", async () => {
    const t = counting();
    expect(isWalletError(await guardedSend(t.transport, post("{}", "http://issuer.practice.invalid/x"), ids, []).catch((x) => x), "NOT_HTTPS")).toBe(true);
    expect(isWalletError(await guardedSend(null, post("{}"), ids, []).catch((x) => x), "OFFLINE")).toBe(true);
    expect(t.calls()).toBe(0);
  });
});

describe("the wallet never phones home", () => {
  test("only the transport module ever calls fetch; no push token, install id or account id exists", () => {
    const src = join(import.meta.dir, "..", "src");
    const files: string[] = [];
    const walk = (dir: string): void => {
      for (const f of readdirSync(dir)) {
        const p = join(dir, f);
        if (statSync(p).isDirectory()) walk(p);
        else if (p.endsWith(".ts")) files.push(p);
      }
    };
    walk(src);
    for (const f of files) {
      const text = readFileSync(f, "utf8");
      const code = text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
      if (!f.endsWith(join("src", "transport.ts")) && !f.includes(join("headless", "scenarios.ts"))) {
        expect({ file: f, fetch: /\bfetch\s*\(|globalThis\.fetch/.test(code) }).toEqual({ file: f, fetch: false });
      }
      expect({ file: f, id: /pushToken|installId|installationId|deviceId|accountId|advertisingId/i.test(code) }).toEqual({ file: f, id: false });
    }
  });
});
