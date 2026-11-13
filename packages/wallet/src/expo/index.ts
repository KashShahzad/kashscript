/**
 * @kashscript/wallet/expo — the person's wallet on a phone: the root in the
 * secure chip, unlocked by face, fingerprint or screen lock.
 *
 * Before anything, it checks the runtime (React Native has no WebCrypto of its
 * own — see `checkRuntime`) and the native module (absent in Expo Go), and it
 * refuses in plain words rather than falling back to a weaker key. A phone
 * with no screen lock, or an Android phone older than 12, cannot hold the
 * root; those people take part by text message or with a file (d42 §7).
 *
 * Apps call `wallet.lock()` when they go to the background.
 */

import { gunzipSync } from "fflate";
import { setInflate, type InflateFunction } from "@kashscript/attest/holder";
import { openWallet, type Wallet } from "../index";
import { copyWith } from "../copy";
import type { WalletConfig } from "../core";
import { WalletError } from "../errors";
import type { Transport } from "../platform";
import { fetchTransport } from "../transport";
import { checkRuntime, explainUnavailable, nativePlatform, type NativeRootModule } from "./adapter";

/** Decompresses RFC 1952 gzip status lists using pure JavaScript fflate. */
export const expoInflate: InflateFunction = (bytes: Uint8Array): Uint8Array => {
  return gunzipSync(bytes);
};

export interface ExpoWalletOptions extends WalletConfig {
  /** Default: `fetch` with no cookies, referrer, cache or redirects. `null`: never send. */
  readonly transport?: Transport | null;
  /** For tests: a stand-in for the native module. */
  readonly native?: NativeRootModule;
}

export async function createExpoWallet(opts: ExpoWalletOptions = {}): Promise<Wallet> {
  setInflate(expoInflate);
  const copy = copyWith(opts.copy);
  const runtime = await checkRuntime();
  if (!runtime.ok) throw new WalletError("RUNTIME_UNSUPPORTED", `missing: ${runtime.missing.join("; ")}`);
  // Loaded only when needed, so tests and non-Expo bundles never reach for expo-modules-core.
  const native = opts.native ?? (await import("./native")).loadNativeRoot();
  if (native === null) throw new WalletError("RUNTIME_UNSUPPORTED", "the KashWalletRoot native module is not in this build (a development build is needed; Expo Go has none)");
  const availability = await native.isAvailable();
  if (!availability.available) throw new WalletError("ROOT_UNAVAILABLE", `${availability.reason ?? "unknown"}: ${explainUnavailable(availability.reason, copy)}`);
  return openWallet(nativePlatform(native, copy, opts.transport === undefined ? fetchTransport() : opts.transport), opts);
}

export { checkRuntime, explainUnavailable, ROOT_ALIAS, type NativeAvailability, type NativeRootModule, type RuntimeCheck, type UnavailableReason } from "./adapter";

