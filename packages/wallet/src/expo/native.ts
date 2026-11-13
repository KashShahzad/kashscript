/** Loads the `KashWalletRoot` native module — absent in Expo Go, on the web, and in tests. */

import { requireOptionalNativeModule } from "expo-modules-core";
import type { NativeRootModule } from "./adapter";

export function loadNativeRoot(): NativeRootModule | null {
  return requireOptionalNativeModule<NativeRootModule>("KashWalletRoot");
}
