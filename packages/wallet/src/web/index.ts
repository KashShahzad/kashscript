/**
 * @kashscript/wallet/web — the wallet in a browser: the organisation's own
 * wallet inside the portal (d44, d47(a)), or a person's where no phone app is
 * used. **Weaker, and labelled so.**
 *
 * The root is a WebCrypto P-256 key made for key agreement only and stored
 * non-extractable in IndexedDB: no script can read its private half, but any
 * script running on this origin can USE it, there is no face, fingerprint or
 * screen lock in front of it, and clearing the site's data destroys it. A
 * phone's secure chip is better on every count, so `root().info.weaker` is
 * true, the words say so, and creating one needs `acknowledgeWeaker: true`.
 * Passkeys are not used as a gate here: passkeys authenticate, device keys
 * sign, and the two are never conflated (d47(g)).
 */

import { openWallet, type Wallet } from "../index";
import { copyWith } from "../copy";
import type { WalletConfig } from "../core";
import { WalletError } from "../errors";
import { newAgreementKeyPair, softwareRoot } from "../adapters/software-root";
import { MemoryStore } from "../adapters/memory-store";
import { systemClock, systemRandom, type BlobStore, type RootInfo, type Transport } from "../platform";
import { fetchTransport } from "../transport";
import { indexedDbBackend } from "./idb";

/** Where a browser wallet keeps its root and its sealed blobs. */
export interface WebBackend {
  getRoot(): Promise<CryptoKeyPair | null>;
  putRoot(pair: CryptoKeyPair): Promise<void>;
  readonly store: BlobStore;
}

/** A backend that forgets everything when the page goes — for tests and demos only. */
export function memoryWebBackend(): WebBackend {
  let root: CryptoKeyPair | null = null;
  return {
    getRoot: async () => root,
    putRoot: async (pair) => {
      root = pair;
    },
    store: new MemoryStore(),
  };
}

export interface WebWalletOptions extends WalletConfig {
  /** Required: a browser keeps keys less safely than a phone's secure chip. */
  readonly acknowledgeWeaker: true;
  /** Default: IndexedDB, database "wallet". */
  readonly backend?: WebBackend;
  /** Default: `fetch` with no cookies, referrer, cache or redirects. `null`: never send. */
  readonly transport?: Transport | null;
}

export async function createWebWallet(opts: WebWalletOptions): Promise<Wallet> {
  if (opts.acknowledgeWeaker !== true) throw new WalletError("WEAKER_NOT_ACKNOWLEDGED");
  const copy = copyWith(opts.copy);
  const backend = opts.backend ?? indexedDbBackend();
  const info: RootInfo = { strength: "browser", where: "browser", unlock: "none", weaker: true, text: copy.rootBrowser };
  return openWallet(
    {
      roots: {
        open: async () => {
          const pair = await backend.getRoot();
          return pair === null ? null : softwareRoot(pair, info);
        },
        create: async () => {
          const pair = await newAgreementKeyPair();
          await backend.putRoot(pair);
          return softwareRoot(pair, info);
        },
      },
      store: backend.store,
      random: systemRandom,
      now: systemClock,
      transport: opts.transport === undefined ? fetchTransport() : opts.transport,
    },
    opts,
  );
}

export { indexedDbBackend } from "./idb";
