/**
 * Terms blueprint — `kash add terms`.
 *
 * Scaffolds an agreement with a declared split. It is what `kash add trade` became
 * (ecosystem d59): @kashscript/terms carries the agreement kernel of the retired
 * trade-core, minus everything that held value. It divides an amount into shares that
 * add up exactly, runs the agreement's lifecycle as a pure function, and signs a record
 * that it concluded. It moves nothing and holds no balance. Apache-2.0.
 */

import type { Blueprint } from "./types";

export const TERMS_BLUEPRINT: Blueprint = {
  id: "terms",
  title: "Kash Terms",
  description: "Agreements with a declared split — a booking, a pass, a bounty, a cohort. Moves nothing (Apache-2.0).",
  blueprintVersion: "0.1.0",

  operations: [
    {
      kind: "install-dep",
      description: "Install the agreements package.",
      spec: { name: "@kashscript/terms", version: "^0.1.0" },
    },
    {
      kind: "install-dep",
      description: "Install identity-core (a share's party is a did:kash).",
      spec: { name: "@kashscript/identity-core", version: "^0.3.0" },
    },
    {
      kind: "write-file",
      description: "Scaffold lib/agreement.ts.",
      path: "lib/agreement.ts",
      managed: false,
      content: () => `/**
 * lib/agreement.ts — scaffolded by \`kash add terms\`.
 *
 * An agreement with a declared split. @kashscript/terms moves nothing and holds no
 * balance: the payer pays on their own rail, and what goes in the book is the declaration.
 *
 *   declaredSplit      the shares for an amount, adding up to it exactly (no dust)
 *   compileManifest    validate and seal an agreement: a booking, a pass, a bounty, a cohort
 *   transition         the agreement's lifecycle, as a pure function
 *   completion receipt a signed record that it concluded. It proves the issuer signed a
 *                      statement about one agreement; it does not prove money moved.
 *
 * Time is Unix seconds (UTC) and the caller passes \`now\`: nothing here reads a clock.
 */

import { declaredSplit, type DeclaredSplit, type ShareLeg } from "@kashscript/terms";

// import { compileManifest, transition } from "@kashscript/terms";

/**
 * Divide \`amount\` (integer minor units) into the shares an agreement declares.
 *
 * Each leg's \`did\` is the party the share is for, and the legs' \`bps\` add up to 10_000.
 * Exactly one leg sets \`sweepFinal\` (it takes the rounding remainder), unless you pass a
 * rounding holder to \`declaredSplit\` yourself.
 */
export function declareShares(amount: bigint, legs: readonly ShareLeg[]): DeclaredSplit {
  return declaredSplit(legs, amount);
}
`,
    },
    {
      kind: "patch-tsconfig",
      description: "Add \`@/lib/agreement\` path alias (skipped when no tsconfig.json).",
      path: "compilerOptions.paths",
      strategy: "merge",
      value: { "@/lib/agreement": ["./lib/agreement.ts"] },
      requires: { tsconfigExists: true },
    },
    {
      kind: "patch-turbo-json",
      description: "Register kash:doctor as a turbo task (monorepo-turbo only).",
      path: "tasks.kash:doctor",
      strategy: "set-if-missing",
      value: { cache: false, persistent: false },
      requires: { paradigm: ["monorepo-turbo"] },
    },
  ],

  verifications: [
    { kind: "dep-present", description: "terms dependency present.", name: "@kashscript/terms" },
    { kind: "file-exists", description: "lib/agreement.ts exists.", path: "lib/agreement.ts" },
  ],
};
