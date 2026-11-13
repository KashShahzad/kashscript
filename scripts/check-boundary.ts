#!/usr/bin/env bun
/**
 * scripts/check-boundary.ts — enforce the licensing/publishing boundary.
 *
 * The monorepo mixes three publishing tiers in one tree (ADR-0007,
 * docs/legal/license-matrix.md is the single source of truth):
 *
 *   PERMISSIVE_PUBLIC     — Apache-2.0. Publishes to public npm. d87's test:
 *                           whatever checking a record or the person's wallet
 *                           needs is open.
 *   COMMERCIAL_RESTRICTED — SSLA Schedule B. Tools that checking does not need
 *                           (d87): published as npm PRIVATE packages
 *                           (`access: "restricted"` on registry.npmjs.org, so
 *                           the @kashscript names stay). Never through the
 *                           public publish workflow (publish-to-npmjs.ts).
 *   INTERNAL              — never reaches public npm (private: true, or a
 *                           non-npmjs registry such as the local Verdaccio).
 *
 * Rules enforced per tier:
 *   • PERMISSIVE_PUBLIC MUST declare `publishConfig.access: "public"`, MUST NOT
 *     be `private: true`, MUST point at registry.npmjs.org (when a registry
 *     is set), and MUST ship a LICENSE file.
 *   • COMMERCIAL_RESTRICTED MUST declare `publishConfig.access: "restricted"`,
 *     MUST NOT be `private: true` (it has to be publishable), MUST point at
 *     registry.npmjs.org (when a registry is set), and MUST ship a LICENSE file.
 *   • INTERNAL MUST be `private: true` OR (`access: "restricted"` AND a
 *     non-npmjs registry). An absent publishConfig on a non-private
 *     package defaults npm to PUBLIC — the exact footgun this rejects.
 *   • Every `@kashscript/*` package under packages/ or services/ MUST be
 *     classified below. Unknown names fail the build.
 *
 * Run by CI (.github/workflows/ci.yml) and before any manual publish.
 * Fails the build listing ALL violations.
 */

import { readdirSync, existsSync, readFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";

const ROOT = resolve(__dirname, "..");
const NPMJS = "https://registry.npmjs.org/";

/**
 * The authoritative tier split. Keep in sync with
 * docs/legal/license-matrix.md.
 */
const PERMISSIVE_PUBLIC = new Set<string>([
  "@kashscript/identity-core",
  "@kashscript/identity-sdk",
  "@kashscript/identity-server", // M2 server identity + agent-identity — identity is free (ADR-0016)
  "@kashscript/lexicons",
  "@kashscript/kash",
  "@kashscript/attest", // M1 evidence commons — verification is free (ADR-0016)
  "@kashscript/muffler", // M3 data protocol — portable hosting is free (ADR-0016)
  "@kashscript/wallet", // PL-6 the holder's wallet — holding, presenting and checking are free (d42 §2, d50(a))
  "@kashscript/terms",  // KS-R3 agreements with a declared split — Apache-2.0, members and outside issuers build on it (d59, d60)
  "@kashscript/whiffin", // KS-R4 the mandate protocol — it never moves money, so the Commercial reason is gone; Apache-2.0 from 0.2.1
  "@kashscript/predicate", // KS-Q1 the wallet's rule engine — checking needs it (d59); Apache-2.0
  "@kashscript/identity-zkp", // d87 — checking and the wallet need it and the open whiffin depends on it; Apache-2.0 from 0.2.4 (0.2.1–0.2.3 stay SSLA)
]);

const COMMERCIAL_RESTRICTED = new Set<string>([
  // Empty since 2026-11-02 (KS-P1, ADR-0024): neuron and hudhud left this repository for Oreoasis's
  // workspace, unpublished. The tier stays for any future closed package that checking does not need.
]);

const INTERNAL = new Set<string>([
  "@kashscript/kash-registry", // operated service, not a library
  "@kashscript/muffler-pds",   // M3 dev-grade reference PDS host — not published (ADR-0016)
  "@kashscript/brand-assets",  // internal brand tokens/glyphs for the apps — private, never published
  "@kashscript/catalog",       // internal product catalog (single source for the site) — private, never published
  // trade-core and trade-sdk (retired by d59, KS-R3; unpublished 2026-11-02) left the tree at AU-11.
]);

/**
 * The one public repository the open packages publish from (AU-11, ADR-0028). npm checks each
 * package's `repository.url` against the source repository in its provenance and refuses a
 * mismatch (E422), so every PERMISSIVE_PUBLIC package names it, with its own directory.
 */
const PUBLIC_REPOSITORY = "KashShahzad/kashscript";
const PUBLIC_REPOSITORY_URL = `git+https://github.com/${PUBLIC_REPOSITORY}.git`;

interface PkgJson {
  readonly name?: string;
  readonly private?: boolean;
  readonly license?: string;
  readonly repository?: string | { readonly type?: string; readonly url?: string; readonly directory?: string };
  readonly publishConfig?: {
    readonly access?: "public" | "restricted";
    readonly registry?: string;
  };
}

interface Violation {
  readonly file: string;
  readonly name: string;
  readonly reason: string;
}

function walk(): readonly { dir: string; pj: PkgJson; file: string }[] {
  const out: { dir: string; pj: PkgJson; file: string }[] = [];
  for (const sub of ["packages", "services"]) {
    const root = join(ROOT, sub);
    if (!existsSync(root)) continue;
    for (const entry of readdirSync(root, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const file = join(root, entry.name, "package.json");
      if (!existsSync(file)) continue;
      const pj = JSON.parse(readFileSync(file, "utf-8")) as PkgJson;
      out.push({ dir: join(root, entry.name), pj, file });
    }
  }
  return out;
}

function normalizeRegistry(r: string | undefined): string | undefined {
  return r ? (r.endsWith("/") ? r : `${r}/`) : undefined;
}

function check(): readonly Violation[] {
  const violations: Violation[] = [];
  for (const { dir, pj, file } of walk()) {
    if (!pj.name || !pj.name.startsWith("@kashscript/")) continue;

    const expectedPermissive = PERMISSIVE_PUBLIC.has(pj.name);
    const expectedRestricted = COMMERCIAL_RESTRICTED.has(pj.name);
    const expectedInternal = INTERNAL.has(pj.name);

    if (!expectedPermissive && !expectedRestricted && !expectedInternal) {
      violations.push({
        file, name: pj.name,
        reason: "Package is not classified in scripts/check-boundary.ts. " +
                "Add it to PERMISSIVE_PUBLIC, COMMERCIAL_RESTRICTED, or INTERNAL, " +
                "and to docs/legal/license-matrix.md.",
      });
      continue;
    }

    const access = pj.publishConfig?.access;
    const registry = normalizeRegistry(pj.publishConfig?.registry);

    if (expectedPermissive || expectedRestricted) {
      const want = expectedPermissive ? "public" : "restricted";
      const kind = expectedPermissive ? "publicly published" : "a private npm package";
      if (pj.private === true) {
        violations.push({
          file, name: pj.name,
          reason: `Classified as ${kind} but \`private: true\` is set.`,
        });
      }
      if (access !== want) {
        violations.push({
          file, name: pj.name,
          reason: `Classified as ${kind} but package.json does not ` +
                  `declare \`publishConfig.access: "${want}"\`.`,
        });
      }
      if (registry !== undefined && registry !== NPMJS) {
        violations.push({
          file, name: pj.name,
          reason: `Classified as ${kind} but publishConfig.registry ` +
                  `points at ${registry} instead of ${NPMJS}.`,
        });
      }
      const wantLicense = expectedPermissive ? "Apache-2.0" : "SEE LICENSE IN LICENSE";
      if (pj.license !== wantLicense) {
        violations.push({
          file, name: pj.name,
          reason: `Classified as ${kind} but package.json declares license ` +
                  `${JSON.stringify(pj.license)} instead of ${JSON.stringify(wantLicense)}.`,
        });
      }
      if (!existsSync(join(dir, "LICENSE")) && !existsSync(join(dir, "LICENSE.md"))) {
        violations.push({
          file, name: pj.name,
          reason: "Published package is missing its LICENSE file " +
                  "(Apache-2.0 or SSLA Schedule B per docs/legal/license-matrix.md).",
        });
      }
    }

    if (expectedPermissive) {
      const repo = typeof pj.repository === "object" ? pj.repository : undefined;
      const wantDir = `packages/${basename(dir)}`;
      if (repo?.url !== PUBLIC_REPOSITORY_URL || repo?.directory !== wantDir) {
        violations.push({
          file, name: pj.name,
          reason: `Publicly published packages must declare \`repository: { "type": "git", "url": ` +
                  `"${PUBLIC_REPOSITORY_URL}", "directory": "${wantDir}" }\` — npm refuses provenance ` +
                  `whose source repository does not match (AU-11).`,
        });
      }
    }

    if (expectedInternal) {
      const restrictedOffNpm =
        access === "restricted" && registry !== undefined && registry !== NPMJS;
      if (pj.private !== true && !restrictedOffNpm) {
        violations.push({
          file, name: pj.name,
          reason: "Classified INTERNAL but package.json neither declares " +
                  "`private: true` nor (`publishConfig.access: \"restricted\"` " +
                  "with a non-npmjs registry). Risk: npm defaults scoped " +
                  "publishConfig-less packages toward the public registry.",
        });
      }
    }
  }
  return violations;
}

const violations = check();
if (violations.length === 0) {
  console.log("✓ licensing/publishing boundary OK");
  process.exit(0);
}
console.error(`✗ ${violations.length} boundary violation(s):`);
for (const v of violations) {
  console.error(`  - ${v.name}`);
  console.error(`    ${v.file}`);
  console.error(`    ${v.reason}`);
}
process.exit(1);
