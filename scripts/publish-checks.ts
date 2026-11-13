/**
 * scripts/publish-checks.ts — the trusted-publishing checks, kept pure so they can be tested.
 *
 * Kept out of publish-to-npmjs.ts (which runs `main()` on import). RW-2, P6 (ECOSYSTEM d84(f)):
 *
 *   1. No npm credential is in reach of a trusted publish — not in the environment, not in an
 *      `.npmrc`. Trusted publishing exchanges the job's OIDC identity for a short-lived credential;
 *      a long-lived token beside it would be a second, unaudited way in.
 *   2. npm's OIDC token exchange answers whether npmjs.com has a trusted publisher for a package —
 *      the same request `npm publish` makes (npm 11, lib/utils/oidc.js), read without npm's log.
 *   3. Provenance is required, and npm generates it only from a public source repository
 *      ("Provenance generation is not supported for private repositories, even when publishing
 *      public packages" — docs.npmjs.com/trusted-publishers). The OIDC token says which.
 *
 * Nothing here prints or stores a token. `oidcClaims` reads a JWT's payload without verifying it —
 * the registry verifies; these checks only refuse early, with a stated reason.
 */

/** Variable names that carry an npm credential: `NODE_AUTH_TOKEN`, `NPM_TOKEN`, npm's own config keys. */
const NAMED = new Set(["NODE_AUTH_TOKEN", "NPM_TOKEN"]);
// npm's credential keys are `_auth`, `_authToken` and `_password`, bare or under `//host/:` — never
// `always-auth`, which is a boolean.
const NPM_CONFIG_AUTH = /^npm_config_(\/\/.*:)?_(authtoken|auth|password)$/i;
const SCOPED_AUTH = /:_(authtoken|auth|password)$/i;

/** The names (never the values) of environment variables that hold a non-empty npm credential. */
export function npmAuthInEnv(env: Readonly<Record<string, string | undefined>>): string[] {
  const found: string[] = [];
  for (const [name, value] of Object.entries(env)) {
    if (!value) continue;
    if (NAMED.has(name) || NPM_CONFIG_AUTH.test(name) || SCOPED_AUTH.test(name)) found.push(name);
  }
  return found.sort();
}

/**
 * True when an `.npmrc` text sets a credential (`_authToken`, `_auth` or `_password`, scoped or not)
 * on a line that is not a comment. A `${NPM_TOKEN}` reference counts: it is a token path.
 */
export function npmrcHasAuth(text: string): boolean {
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#") || line.startsWith(";")) continue;
    const eq = line.indexOf("=");
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim();
    if (/(^|:)_(authToken|auth|password)$/i.test(key)) return true;
  }
  return false;
}

/** The claims of a GitHub Actions OIDC token that the checks read. */
export interface OidcClaims {
  readonly repository?: string;
  readonly repository_visibility?: string;
  readonly ref?: string;
  readonly environment?: string;
  readonly workflow_ref?: string;
}

/** Decode a JWT's payload. Throws on a malformed token; never verifies (the registry does). */
export function oidcClaims(jwt: string): OidcClaims {
  const parts = jwt.split(".");
  if (parts.length !== 3 || !parts[1]) throw new Error("the OIDC token is not a JWT");
  const json = Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
  const payload = JSON.parse(json) as Record<string, unknown>;
  const pick = (k: string): string | undefined => (typeof payload[k] === "string" ? (payload[k] as string) : undefined);
  return {
    repository: pick("repository"),
    repository_visibility: pick("repository_visibility"),
    ref: pick("ref"),
    environment: pick("environment"),
    workflow_ref: pick("workflow_ref"),
  };
}

export type ProvenanceVerdict = { readonly ok: true } | { readonly ok: false; readonly reason: string };

/** Provenance is required (RW-2), and npm generates it only from a public repository. */
export function provenanceVerdict(claims: OidcClaims): ProvenanceVerdict {
  const repo = claims.repository ?? "(unknown repository)";
  if (claims.repository_visibility === "public") return { ok: true };
  return {
    ok: false,
    reason:
      `provenance impossible: ${repo} is ${claims.repository_visibility ?? "of unknown visibility"} — ` +
      `npm generates provenance only from a public source repository, and RW-2 publishes nothing without it, ` +
      `so a real publish refuses. Making the repository public, or publishing from a public mirror, is the ` +
      `founder's decision (docs/publishing.md).`,
  };
}

export type ExchangeOutcome = { readonly configured: true } | { readonly configured: false; readonly reason: string };

/**
 * Read npm's OIDC token-exchange response. A 2xx carrying a token means npmjs.com has a trusted
 * publisher matching this repository, workflow and environment. Anything else is "not configured",
 * with npm's own message when it gives one.
 */
export function exchangeOutcome(status: number, body: unknown): ExchangeOutcome {
  const b = (body && typeof body === "object" ? body : {}) as { token?: unknown; message?: unknown; error?: unknown };
  if (status >= 200 && status < 300 && typeof b.token === "string" && b.token.length > 0) return { configured: true };
  const said = typeof b.message === "string" ? b.message : typeof b.error === "string" ? b.error : "";
  return { configured: false, reason: said ? `HTTP ${status}: ${said}` : `HTTP ${status}` };
}

/** npm's escaped package name for registry paths: `@scope/name` → `@scope%2fname` (npm-package-arg). */
export function escapedName(name: string): string {
  return name.replace("/", "%2f");
}

/** A package.json `repository` field: a string shorthand or an object. */
export type RepositoryField = string | { readonly type?: string; readonly url?: string; readonly directory?: string } | undefined;

/** `owner/name` from a GitHub repository URL (`git+https://github.com/o/n.git`, `https://…`, `git://…`), lowercased; undefined otherwise. */
export function githubRepoOf(url: string): string | undefined {
  const m = /^(?:git\+)?(?:https?|git|ssh):\/\/(?:git@)?github\.com\/([^/\s]+)\/([^/\s]+?)(?:\.git)?\/?$/i.exec(url.trim());
  return m ? `${m[1]}/${m[2]}`.toLowerCase() : undefined;
}

/**
 * npm checks a package's `repository.url` against the source repository its provenance names and
 * refuses a mismatch (E422, after the build and the signing). AU-11: refuse early, with the reason —
 * the field must name the repository this run publishes from (`GITHUB_REPOSITORY`) and the package's
 * own directory.
 */
export function repositoryVerdict(field: RepositoryField, githubRepository: string | undefined, slug: string): ProvenanceVerdict {
  const want = `packages/${slug}`;
  if (!githubRepository) return { ok: false, reason: "GITHUB_REPOSITORY is not set — a trusted publish runs only in GitHub Actions" };
  const obj = typeof field === "object" ? field : undefined;
  const url = typeof field === "string" ? field : obj?.url;
  if (!url) {
    return { ok: false, reason: `package.json has no repository.url — npm refuses provenance from ${githubRepository} without one (E422). Add { "type": "git", "url": "git+https://github.com/${githubRepository}.git", "directory": "${want}" }` };
  }
  const named = githubRepoOf(url);
  if (named !== githubRepository.toLowerCase()) {
    return { ok: false, reason: `package.json's repository.url names ${named ?? JSON.stringify(url)}, but this run publishes from ${githubRepository} — npm would refuse the provenance (E422)` };
  }
  if (obj?.directory !== want) {
    return { ok: false, reason: `package.json's repository.directory is ${JSON.stringify(obj?.directory)}, expected "${want}"` };
  }
  return { ok: true };
}
