/**
 * Identity blueprint — `kash add identity`.
 *
 * Wires the @kashscript/identity-core + identity-sdk pair into the user's
 * project: installs deps, scaffolds `/lib/kash.ts` (the application's local
 * SDK re-export module), drops a `<KashLogin />` component when Next.js is
 * detected, registers a `kash:doctor` npm script, and adds a TS path
 * alias for `@/lib/kash` so deeply-nested files don't import via `../../`.
 *
 * Idempotent: every operation introspects current state and is a no-op
 * when the desired post-condition is already present. Re-running
 * `kash add identity` is safe.
 *
 * One path, no licence tier. identity-core and identity-sdk are Apache-2.0
 * (ecosystem d87; `docs/legal/license-matrix.md`), so the scaffold imports the
 * SDK's UI like any dependency and asks for no badge; restyle or fork the
 * components under the licence's own terms. The "KSL §3" tiers (community ·
 * business · enterprise), the required "Powered by Kash" badge and the
 * white-label copies that came with them were removed on 2026-11-02 together
 * with the Kash Sovereign License that alone justified them
 * (`docs/archive/kash-sovereign-license-2026-05-11.md`).
 */

import type { Blueprint, RenderContext } from "./types";

const CORE_VERSION = "^0.3.0"; // identity-core is published at 0.3.1 — ^0.2.0 matched nothing
const SDK_VERSION  = "^0.1.0";

export const IDENTITY_BLUEPRINT: Blueprint = {
  id: "identity",
  title: "Kash Identity",
  description: "did:kash + Passkeys + signed Kash-Events. Bring user-owned identity into your app.",
  blueprintVersion: "0.4.0",

  operations: [
    /* ── 1. dependencies ─────────────────────────────────────── */
    {
      kind: "install-dep",
      description: "Install identity-core (zero-dep cryptography).",
      spec: { name: "@kashscript/identity-core", version: CORE_VERSION },
    },
    {
      kind: "install-dep",
      description: "Install identity-sdk (React provider + hooks + UI).",
      spec: { name: "@kashscript/identity-sdk", version: SDK_VERSION },
    },

    /* ── 2. scaffold the application's local SDK module ─────── */
    {
      kind: "write-file",
      description: "Scaffold lib/kash.ts — your app's identity entry point.",
      path: "lib/kash.ts",
      managed: false,
      content: (ctx) => libKashSource(ctx),
    },

    /* ── 3. starter login component (Next.js only) ──────────── */
    {
      kind: "write-file",
      description: "Scaffold components/KashLogin.tsx (Next.js apps only).",
      path: "components/KashLogin.tsx",
      managed: false,
      when: ({ env }) => env.framework === "next",
      content: () => kashLoginComponentSource(),
    },

    /* ── 4. add a 'kash:doctor' npm script ─────────────────── */
    {
      kind: "patch-package-json",
      description: "Add `npm run kash:doctor` script.",
      path: "scripts.kash:doctor",
      strategy: "set-if-missing",
      value: "kash doctor",
    },

    /* ── 5. TS path alias so `import "@/lib/kash"` just works ─ */
    {
      kind: "patch-tsconfig",
      description: "Register `@/lib/kash` as a TS path alias (skipped when no tsconfig.json).",
      path: "compilerOptions.paths",
      strategy: "merge",
      value: { "@/lib/kash": ["./lib/kash.ts"] },
      requires: { tsconfigExists: true },
    },

    /* ── 6. Turbo task registration (monorepo-turbo only) ──── */
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
    {
      kind: "dep-present",
      description: "identity-core dependency is installed.",
      name: "@kashscript/identity-core",
      versionStartsWith: "^0.",
    },
    {
      kind: "dep-present",
      description: "identity-sdk dependency is installed.",
      name: "@kashscript/identity-sdk",
      versionStartsWith: "^0.",
    },
    {
      kind: "file-exists",
      description: "lib/kash.ts is present.",
      path: "lib/kash.ts",
    },
    {
      kind: "package-json-field",
      description: "scripts.kash:doctor is registered.",
      path: "scripts.kash:doctor",
    },
  ],
};

/* ── file content templates ─────────────────────────────────────── */

/** Any framework that ships React (incl. CRA + generic React + Remix + Expo + Vite). */
const REACT_FRAMEWORKS: ReadonlySet<string> = new Set([
  "next", "vite", "remix", "expo", "cra", "react",
]);

function libKashSource(ctx: RenderContext): string {
  const isReact = REACT_FRAMEWORKS.has(ctx.env.framework);

  return `/**
 * lib/kash.ts — scaffolded by \`kash add ${ctx.product}\` (Kash Identity blueprint v0.4).
 *
 * This module is YOURS — edit freely. Re-running \`kash add identity\` will
 * NOT touch it; pass \`--force\` if you want the latest scaffold.
 */

${isReact
  ? `export {
  KashAuthProvider,
  useKashAuth,
  useKashIdentity,
  useSigner,
} from "@kashscript/identity-sdk";

export type {
  KashIdentity,
  KashAuthContextValue,
} from "@kashscript/identity-sdk";

// The SDK's UI components, imported like any dependency (Apache-2.0). Fork them
// into your own tree whenever you need full visual control.
export { KashConnect, IdentityWidget, SignTransactionModal } from "@kashscript/identity-sdk/ui";
`
  : `export { generateKeyPair, exportKey, importKey, deriveDid, createDidDocument } from "@kashscript/identity-core";
export type { KashKeyPair, ExportedKey, KashDid, DidDocument } from "@kashscript/identity-core";
`}

/** Your application's WebAuthn Relying Party name shown in OS prompts. */
export const KASH_RP_NAME = "MyApp";
`;
}

function kashLoginComponentSource(): string {
  return `"use client";

/**
 * components/KashLogin.tsx — scaffolded by \`kash add identity\`.
 *
 * Drop this anywhere in your Next.js tree. \`KashAuthProvider\` must already
 * wrap your root layout — see the README \`Quickstart\` in @kashscript/identity-sdk.
 */

import { KashConnect } from "@kashscript/identity-sdk/ui";

export function KashLogin(): React.ReactElement {
  return (
    <div className="flex flex-col items-center justify-center p-6 gap-3">
      <KashConnect />
    </div>
  );
}
`;
}
