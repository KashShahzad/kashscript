/**
 * HMAC-DRBG (NIST SP 800-90A, SHA-256, no reseed) — the headless mode's random
 * source, so a practice run with the same seed makes the same relationship keys
 * and names, and a failure reproduces. **Practice only:** a real wallet uses
 * the platform's random source, never this.
 */

import type { Random } from "../platform";
import { buf, concat, utf8 } from "./bytes";

async function hmac(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey("raw", buf(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, buf(data)));
}

export function seededRandom(seed: string | Uint8Array): Random {
  const material = typeof seed === "string" ? utf8(seed) : seed;
  let K: Uint8Array = new Uint8Array(32);
  let V: Uint8Array = new Uint8Array(32).fill(0x01);
  let ready: Promise<void> | null = null;

  const update = async (data: Uint8Array): Promise<void> => {
    K = await hmac(K, concat(V, Uint8Array.of(0x00), data));
    V = await hmac(K, V);
    if (data.length > 0) {
      K = await hmac(K, concat(V, Uint8Array.of(0x01), data));
      V = await hmac(K, V);
    }
  };

  // One generate at a time, so concurrent callers still get a fixed sequence.
  let queue: Promise<unknown> = Promise.resolve();
  return (length: number) => {
    const next = queue.then(async () => {
      ready ??= update(material);
      await ready;
      const out = new Uint8Array(length);
      for (let at = 0; at < length; ) {
        V = await hmac(K, V);
        const take = Math.min(V.length, length - at);
        out.set(V.slice(0, take), at);
        at += take;
      }
      await update(new Uint8Array(0));
      return out;
    });
    queue = next;
    return next;
  };
}
