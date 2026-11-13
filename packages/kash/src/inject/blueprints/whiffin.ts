/**
 * Whiffin blueprint — `kash add whiffin`.
 *
 * Scaffolds the purpose-bound mandate flow (issue → deliver → redeem) with the
 * config-driven policy gate. Since 0.2.0 whiffin is the mandate protocol and never
 * moves money (ecosystem d59, d41): the payer pays on their own rail, and arrival is
 * proven by the recipient's second signature. Its licence is Apache-2.0 from 0.2.1
 * (0.2.0 was published under SSLA Schedule B).
 */

import type { Blueprint } from "./types";

export const WHIFFIN_BLUEPRINT: Blueprint = {
  id: "whiffin",
  title: "Kash Whiffin",
  description: "Purpose-bound mandates (W3C VC, AP2 semantics) with an arrival clause and an offline-checkable report. It never moves money.",
  blueprintVersion: "0.2.0",

  operations: [
    {
      kind: "install-dep",
      description: "Install the whiffin mandate protocol.",
      spec: { name: "@kashscript/whiffin", version: "^0.2.0" },
    },
    {
      kind: "write-file",
      description: "Scaffold lib/whiffin-mandate.ts.",
      path: "lib/whiffin-mandate.ts",
      managed: false,
      content: () => `/**
 * lib/whiffin-mandate.ts — scaffolded by \`kash add whiffin\`.
 *
 * A mandate is a purpose-bound grant (a W3C Verifiable Credential with AP2 Intent Mandate
 * semantics): a fixed maximum amount, a purpose lock, an allowed-vendor set (a Merkle
 * root), a REQUIRED end date, a single-use nonce, and who confirms arrival: the recipient,
 * with a second signature. The lifecycle is issueGrant -> markDelivered -> redeemGrant,
 * gated by a config-driven, ordered policy (signature -> beneficiary -> purpose -> expiry
 * -> vendor inclusion, nonce burned LAST).
 *
 * It NEVER MOVES MONEY. The payer pays on their own rail; this package signs the
 * declaration and checks the recipient's confirmation. The rails' names (\`RAIL\`) are an
 * enum a declaration can cite. There is no adapter to call, and nothing here marks a
 * payment done on its own say.
 *
 * Licence: Apache-2.0 from 0.2.1. See the LICENSE of the version you installed.
 */

// import { issueGrant, markDelivered, redeemGrant, InMemoryGrantLedger, InMemoryNonceStore } from "@kashscript/whiffin/mandate";
// import { toMandateCredential, verifyMandateCredential } from "@kashscript/whiffin/credential";
// import { RAIL } from "@kashscript/whiffin/rails";
// import { assembleSignedReport } from "@kashscript/whiffin/report";

export interface WhiffinMandateConfig {
  /** The circuit the mandates belong to (whiffin's own field name). */
  readonly programId: string;
  /** The grant authority's did:kash — signs every mandate. */
  readonly operatorDid: \`did:kash:\${string}\`;
  /** Approved vendor DIDs — reduced to a Merkle root the policy gate checks. */
  readonly approvedVendorDids: readonly string[];
}

export function createMandateIssuer(_config: WhiffinMandateConfig): never {
  throw new Error(
    "Wire lib/whiffin-mandate.ts to @kashscript/whiffin/mandate: issueGrant -> markDelivered -> " +
    "redeemGrant against your GrantLedger + NonceStore. The payer pays on their own rail; the " +
    "recipient's second signature confirms arrival.",
  );
}
`,
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
    { kind: "dep-present", description: "whiffin dependency present.", name: "@kashscript/whiffin" },
    { kind: "file-exists", description: "lib/whiffin-mandate.ts exists.", path: "lib/whiffin-mandate.ts" },
  ],
};
