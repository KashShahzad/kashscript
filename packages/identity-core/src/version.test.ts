/**
 * Version-sync guard. The exported `IDENTITY_CORE_VERSION` constant is
 * hand-maintained; this test fails the moment it drifts from
 * package.json, so the drift is caught in CI instead of shipping (the
 * exact bug that left identity-zkp's constant at 0.2.0 while the
 * package was 0.2.2).
 */

import { expect, test } from "bun:test";
import pkg from "../package.json";
import { IDENTITY_CORE_VERSION } from "./index";

test("IDENTITY_CORE_VERSION matches package.json version", () => {
  // widen the `as const` literal so toBe compares string-to-string
  expect(IDENTITY_CORE_VERSION as string).toBe(pkg.version);
});
