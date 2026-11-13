/**
 * scripts/sbom.ts — a CycloneDX 1.6 SBOM for one packed @kashscript package (RW-2, P6).
 *
 * CycloneDX is the format (d71: no format of our own); this is only the generator. It is ours, and
 * dependency-free, because the off-the-shelf generators need an npm tree or lockfile and this is a
 * Bun workspace whose packages publish `workspace:*` siblings as exact versions — a sibling being
 * published in the same batch is not on the registry yet, so nothing can resolve it from there.
 *
 * What it reads:
 *   - the PACKED manifest — the package.json that went into the tarball, siblings already exact;
 *   - `@kashscript/*` siblings from `packages/<slug>/package.json`, the one source of truth that
 *     publish-to-npmjs.ts's `mutateAndPack` already resolves from;
 *   - every other package from the installed `node_modules`, resolved the way Node does from the
 *     depending package's directory upward, recursively;
 *   - integrity hashes from `bun.lock` (text lockfile; JSON with trailing commas).
 *
 * What it lists: the runtime closure only — dependencies, optional and peer dependencies, never
 * devDependencies. A required dependency that cannot be found fails the SBOM: an SBOM that leaves a
 * dependency out is worse than none. An optional or peer dependency that is not installed is left out
 * (the consumer's install decides it).
 */

import { existsSync, readFileSync, realpathSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

export interface PackedManifest {
  readonly name: string;
  readonly version: string;
  readonly license?: unknown;
  readonly dependencies?: Readonly<Record<string, string>>;
  readonly optionalDependencies?: Readonly<Record<string, string>>;
  readonly peerDependencies?: Readonly<Record<string, string>>;
  readonly peerDependenciesMeta?: Readonly<Record<string, { optional?: boolean }>>;
}

export interface SbomInput {
  /** The monorepo root: `packages/` and `node_modules/` beneath it. */
  readonly root: string;
  /** The package's own directory; resolution of its dependencies starts here. */
  readonly pkgDir: string;
  /** The manifest as packed into the tarball. */
  readonly manifest: PackedManifest;
  /** SHA-512 of the tarball, hex. */
  readonly tarballSha512Hex: string;
  /** `bun.lock`'s text, for integrity hashes; omitted → components carry no hashes. */
  readonly lockText?: string;
  readonly timestamp: string;
  /** `urn:uuid:…` */
  readonly serialNumber: string;
}

interface Hash { readonly alg: string; readonly content: string }
type License = { readonly expression: string } | { readonly license: { readonly name: string } };

export interface Component {
  readonly type: "library";
  readonly "bom-ref": string;
  readonly group?: string;
  readonly name: string;
  readonly version: string;
  readonly purl: string;
  scope?: "required" | "optional";
  readonly licenses?: readonly License[];
  readonly hashes?: readonly Hash[];
}

export interface CycloneDxBom {
  readonly bomFormat: "CycloneDX";
  readonly specVersion: "1.6";
  readonly serialNumber: string;
  readonly version: 1;
  readonly metadata: {
    readonly timestamp: string;
    readonly tools: { readonly components: readonly { type: "application"; name: string; version: string }[] };
    readonly component: Component;
  };
  readonly components: readonly Component[];
  readonly dependencies: readonly { ref: string; dependsOn: string[] }[];
}

const SCOPE = "@kashscript/";
const GENERATOR = { type: "application" as const, name: "kashscript scripts/sbom.ts", version: "1" };

// ── bun.lock ──────────────────────────────────────────────────────────

/** Remove trailing commas outside strings, so JSON-with-trailing-commas parses as JSON. */
export function stripTrailingCommas(text: string): string {
  let out = "";
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (inString) {
      out += ch;
      if (ch === "\\") {
        out += text[i + 1] ?? "";
        i++;
      } else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') {
      inString = true;
      out += ch;
      continue;
    }
    if (ch === ",") {
      let j = i + 1;
      while (j < text.length && /\s/.test(text[j]!)) j++;
      if (text[j] === "}" || text[j] === "]") continue;
    }
    out += ch;
  }
  return out;
}

/** `name@version` → `sha512-…`, from bun.lock's `packages` entries (`["name@version", registry, {deps}, "sha512-…"]`). */
export function lockIntegrity(lockText: string): Map<string, string> {
  const lock = JSON.parse(stripTrailingCommas(lockText)) as { packages?: Record<string, unknown> };
  const map = new Map<string, string>();
  for (const entry of Object.values(lock.packages ?? {})) {
    if (!Array.isArray(entry) || typeof entry[0] !== "string") continue;
    const id = entry[0];
    const integrity = entry.find((x): x is string => typeof x === "string" && /^sha(256|384|512)-/.test(x));
    if (integrity && !map.has(id)) map.set(id, integrity);
  }
  return map;
}

/** SRI (`sha512-<base64>`) → CycloneDX hash (hex). */
export function sriToHash(sri: string): Hash | undefined {
  const m = /^sha(256|384|512)-(.+)$/.exec(sri);
  if (!m) return undefined;
  return { alg: `SHA-${m[1]}`, content: Buffer.from(m[2]!, "base64").toString("hex") };
}

// ── naming ────────────────────────────────────────────────────────────

/** Package URL for an npm package: `pkg:npm/%40scope/name@version`. */
export function npmPurl(name: string, version: string): string {
  const [ns, base] = name.startsWith("@") ? [name.slice(0, name.indexOf("/")), name.slice(name.indexOf("/") + 1)] : [undefined, name];
  const path = ns ? `${encodeURIComponent(ns)}/${encodeURIComponent(base!)}` : encodeURIComponent(base!);
  return `pkg:npm/${path}@${encodeURIComponent(version)}`;
}

function licensesOf(raw: unknown): License[] | undefined {
  const s =
    typeof raw === "string" ? raw
    : raw && typeof raw === "object" && typeof (raw as { type?: unknown }).type === "string" ? (raw as { type: string }).type
    : undefined;
  if (!s || !s.trim()) return undefined;
  if (/^(SEE LICEN[CS]E IN|UNLICENSED)/i.test(s)) return [{ license: { name: s } }];
  return [{ expression: s }];
}

function component(name: string, version: string, license: unknown, hash?: Hash): Component {
  const purl = npmPurl(name, version);
  const scoped = name.startsWith("@");
  return {
    type: "library",
    "bom-ref": purl,
    ...(scoped ? { group: name.slice(0, name.indexOf("/")) } : {}),
    name: scoped ? name.slice(name.indexOf("/") + 1) : name,
    version,
    purl,
    ...(licensesOf(license) ? { licenses: licensesOf(license) } : {}),
    ...(hash ? { hashes: [hash] } : {}),
  };
}

// ── resolution ────────────────────────────────────────────────────────

interface Manifest extends PackedManifest {
  readonly licenses?: unknown;
}

interface Resolved {
  readonly dir: string;
  readonly manifest: Manifest;
}

function readManifest(path: string): Manifest {
  return JSON.parse(readFileSync(path, "utf8")) as Manifest;
}

/** A sibling from `packages/<slug>`, else Node's resolution from `fromDir` up to `root`. */
function resolvePackage(name: string, fromDir: string, root: string): Resolved | null {
  if (name.startsWith(SCOPE)) {
    const dir = join(root, "packages", name.slice(SCOPE.length));
    const pj = join(dir, "package.json");
    if (existsSync(pj)) {
      const manifest = readManifest(pj);
      if (manifest.name === name) return { dir, manifest };
    }
  }
  const top = resolve(root);
  let dir = resolve(fromDir);
  for (;;) {
    const pj = join(dir, "node_modules", name, "package.json");
    if (existsSync(pj)) return { dir: realpathSync(dirname(pj)), manifest: readManifest(pj) };
    if (dir === top) return null;
    const up = dirname(dir);
    if (up === dir) return null;
    dir = up;
  }
}

interface Edge {
  readonly name: string;
  readonly optional: boolean;
}

function edgesOf(m: PackedManifest): Edge[] {
  const edges: Edge[] = [];
  for (const name of Object.keys(m.dependencies ?? {})) edges.push({ name, optional: false });
  for (const name of Object.keys(m.optionalDependencies ?? {})) edges.push({ name, optional: true });
  for (const name of Object.keys(m.peerDependencies ?? {})) {
    // A peer is the consumer's to install; listed when installed here, never required to be.
    edges.push({ name, optional: true });
  }
  return edges;
}

// ── the SBOM ──────────────────────────────────────────────────────────

export function buildSbom(input: SbomInput): CycloneDxBom {
  const { root, pkgDir, manifest } = input;
  const integrity = input.lockText ? lockIntegrity(input.lockText) : new Map<string, string>();

  const rootComponent = component(manifest.name, manifest.version, manifest.license, { alg: "SHA-512", content: input.tarballSha512Hex });

  const components = new Map<string, Component>(); // bom-ref → component
  const graph = new Map<string, Set<string>>(); // bom-ref → dependsOn
  const required = new Set<string>();
  graph.set(rootComponent["bom-ref"], new Set());

  // Walk the closure. `viaRequired` marks a component reached by a chain of required edges only.
  const queue: { ref: string; manifest: PackedManifest; dir: string; viaRequired: boolean }[] = [
    { ref: rootComponent["bom-ref"], manifest, dir: pkgDir, viaRequired: true },
  ];
  const expanded = new Map<string, boolean>(); // bom-ref → expanded with viaRequired
  while (queue.length > 0) {
    const node = queue.shift()!;
    for (const edge of edgesOf(node.manifest)) {
      const found = resolvePackage(edge.name, node.dir, root);
      if (!found) {
        if (edge.optional) continue;
        throw new Error(
          `${edge.name} (a dependency of ${node.ref}) is not installed — run \`bun install\`; ` +
          `an SBOM that leaves out a required dependency is refused`,
        );
      }
      const { name, version, license, licenses } = found.manifest;
      if (name !== edge.name) throw new Error(`resolved ${edge.name} but its package.json names ${name}`);
      const sri = integrity.get(`${name}@${version}`);
      const c = component(name, version, license ?? (Array.isArray(licenses) ? licenses[0] : undefined), sri ? sriToHash(sri) : undefined);
      const ref = c["bom-ref"];
      if (!components.has(ref)) components.set(ref, c);
      graph.get(node.ref)!.add(ref);
      if (!graph.has(ref)) graph.set(ref, new Set());

      const viaRequired = node.viaRequired && !edge.optional;
      if (viaRequired) required.add(ref);
      const before = expanded.get(ref);
      // Expand once; again only if it is now reached by a required chain and was not before.
      if (before === undefined || (viaRequired && before === false)) {
        expanded.set(ref, viaRequired);
        queue.push({ ref, manifest: found.manifest, dir: found.dir, viaRequired });
      }
    }
  }

  const sorted = [...components.values()]
    .map((c) => ({ ...c, scope: required.has(c["bom-ref"]) ? ("required" as const) : ("optional" as const) }))
    .sort((a, b) => a["bom-ref"].localeCompare(b["bom-ref"]));

  const dependencies = [...graph.entries()]
    .map(([ref, deps]) => ({ ref, dependsOn: [...deps].sort() }))
    .sort((a, b) => (a.ref === rootComponent["bom-ref"] ? -1 : b.ref === rootComponent["bom-ref"] ? 1 : a.ref.localeCompare(b.ref)));

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: input.serialNumber,
    version: 1,
    metadata: {
      timestamp: input.timestamp,
      tools: { components: [GENERATOR] },
      component: rootComponent,
    },
    components: sorted,
    dependencies,
  };
}
