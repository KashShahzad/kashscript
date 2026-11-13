/**
 * A practice stand-in for a phone's secure chip (PL-2): P-256 signing keys
 * held in memory, OUTSIDE the wallet's store — as a chip's keys are — made
 * from the run's seeded random so a failure reproduces, signing ES256 and
 * answering in DER as the chips do. **Practice only**, and labelled so.
 */

import { decompressP256PublicKey, ecdsaRawToDer, p256PublicKeyFromScalar, P256_ORDER, signP256 } from "@kashscript/identity-core";
import type { HardwareSigners, Random } from "../../platform";

export interface PracticeHardware extends HardwareSigners {
  /** How many keys the practice chip holds — so a run can see none was copied out. */
  held(): number;
}

function inRange(d: Uint8Array): boolean {
  let n = 0n;
  for (const b of d) n = (n << 8n) | BigInt(b);
  return n > 0n && n < P256_ORDER;
}

export function practiceHardwareSigners(random: Random, text: string): PracticeHardware {
  const keys = new Map<string, { readonly privateKey: Uint8Array; readonly publicKey: Uint8Array }>();
  let made = 0;
  return {
    info: () => ({ strength: "practice", where: "memory", text }),
    create: async () => {
      let d = await random(32);
      while (!inRange(d)) d = await random(32);
      const publicKey = await p256PublicKeyFromScalar(d);
      const handle = `practice-chip-key-${++made}`;
      keys.set(handle, { privateKey: d, publicKey });
      return { handle, publicKey: decompressP256PublicKey(publicKey) };
    },
    sign: async (handle, message) => {
      const k = keys.get(handle);
      if (k === undefined) throw new Error("no such key in the practice chip");
      return ecdsaRawToDer(await signP256(message, k.privateKey, k.publicKey));
    },
    remove: async (handle) => {
      keys.get(handle)?.privateKey.fill(0);
      keys.delete(handle);
    },
    held: () => keys.size,
  };
}
