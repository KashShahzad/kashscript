/**
 * The headless wallet — no screen and no secure chip, for the simulation
 * (PL-5) and tests. **Practice only, never for a person.**
 *
 * - The root is a WebCrypto key made for key agreement only, held in memory.
 * - The store is in memory; the clock is injected, so expiry is tested with a
 *   clock and never by editing data.
 * - The random source is seeded, so the same seed makes the same relationship
 *   keys and names, and a failure reproduces.
 * - With `hardwareSigning`, a practice stand-in for a phone's secure chip
 *   holds P-256 signing keys outside the store and signs ES256 (PL-2);
 *   without it, keys are Ed25519 sealed by the root, as on the web.
 * - `inspect` shows only what the platform around a wallet could see anyway:
 *   the ciphertext it stores and the requests it sends. Never a key.
 */

import { openWallet, type Wallet } from "../index";
import { copyWith, type Copy } from "../copy";
import { seededRandom } from "../crypto/drbg";
import { WalletError } from "../errors";
import { MemoryStore } from "../adapters/memory-store";
import { newAgreementKeyPair, softwareRoot } from "../adapters/software-root";
import type { Clock, HardwareRoot, HttpRequest, Transport } from "../platform";
import { practiceHardwareSigners, type PracticeHardware } from "./practice/hardware";

export interface HeadlessOptions {
  /** Must be `true`: this wallet is for practice runs, never for a person's records. */
  readonly practice: true;
  readonly seed: string | Uint8Array;
  readonly now?: Clock;
  /** Where requests go. Default: nowhere — the wallet refuses to send. */
  readonly transport?: Transport | null;
  readonly pinnedPublishers?: readonly string[];
  readonly batchSize?: number;
  readonly copy?: Partial<Copy>;
  /** A practice secure chip: relationship and copy keys are P-256, signing ES256 in it. */
  readonly hardwareSigning?: boolean;
}

export interface HeadlessWallet {
  readonly wallet: Wallet;
  readonly inspect: {
    /** Every stored name and byte, as one comparable string. A decline must not change it. */
    snapshot(): string;
    blobs(): ReadonlyMap<string, Uint8Array>;
    /** Every request the wallet actually sent, in order. */
    traffic(): readonly HttpRequest[];
    /** The practice root's public key — so a run can assert it never left. */
    rootPublicKey(): Uint8Array;
    /** Keys held in the practice chip (0 without `hardwareSigning`). They are never in the store. */
    chipKeys(): number;
  };
}

export async function createHeadlessWallet(opts: HeadlessOptions): Promise<HeadlessWallet> {
  if (opts.practice !== true) throw new WalletError("PRACTICE_ONLY");
  const copy = copyWith(opts.copy);
  const store = new MemoryStore();
  const sent: HttpRequest[] = [];
  const inner = opts.transport ?? null;
  const transport: Transport | null =
    inner === null
      ? null
      : async (req) => {
          sent.push(req);
          return inner(req);
        };
  let root: HardwareRoot | null = null;
  const chip: PracticeHardware | null =
    opts.hardwareSigning === true ? practiceHardwareSigners(seededRandom(`${typeof opts.seed === "string" ? opts.seed : Array.from(opts.seed).join(",")}/chip`), copy.rootPractice) : null;
  const wallet = await openWallet(
    {
      roots: {
        open: async () => root,
        create: async () => {
          root = await softwareRoot(await newAgreementKeyPair(), { strength: "practice", where: "memory", unlock: "none", weaker: true, text: copy.rootPractice });
          return root;
        },
      },
      store,
      random: seededRandom(opts.seed),
      now: opts.now ?? (() => Math.floor(Date.now() / 1000)),
      transport,
      signers: chip,
    },
    {
      ...(opts.pinnedPublishers !== undefined ? { pinnedPublishers: opts.pinnedPublishers } : {}),
      ...(opts.batchSize !== undefined ? { batchSize: opts.batchSize } : {}),
      ...(opts.copy !== undefined ? { copy: opts.copy } : {}),
    },
  );
  return {
    wallet,
    inspect: {
      snapshot: () =>
        [...store.snapshot().entries()]
          .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
          .map(([name, bytes]) => `${name}=${[...bytes].map((b) => b.toString(16).padStart(2, "0")).join("")}`)
          .join("\n"),
      blobs: () => store.snapshot(),
      traffic: () => [...sent],
      rootPublicKey: () => (root as HardwareRoot).publicKey(),
      chipKeys: () => chip?.held() ?? 0,
    },
  };
}
