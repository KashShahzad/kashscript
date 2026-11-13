import { describe, expect, test } from "bun:test";
import {
  escapedName,
  exchangeOutcome,
  npmAuthInEnv,
  npmrcHasAuth,
  oidcClaims,
  provenanceVerdict,
  githubRepoOf,
  repositoryVerdict,
} from "./publish-checks";

function jwt(payload: Record<string, unknown>): string {
  const b64url = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b64url({ alg: "RS256", typ: "JWT" })}.${b64url(payload)}.c2lnbmF0dXJl`;
}

describe("npmAuthInEnv", () => {
  test("names every npm credential, never the value", () => {
    const found = npmAuthInEnv({
      NODE_AUTH_TOKEN: "XXXXX-XXXXX-XXXXX-XXXXX", // what setup-node writes with registry-url
      NPM_TOKEN: "npm_secret",
      npm_config__authToken: "a",
      "npm_config_//registry.npmjs.org/:_authToken": "b",
      NPM_CONFIG__AUTH: "c",
      npm_config__password: "d",
    });
    expect(found).toEqual([
      "NODE_AUTH_TOKEN",
      "NPM_CONFIG__AUTH",
      "NPM_TOKEN",
      "npm_config_//registry.npmjs.org/:_authToken",
      "npm_config__authToken",
      "npm_config__password",
    ]);
    expect(found.join(" ")).not.toContain("npm_secret");
  });

  test("ignores the job's own credentials and empty values", () => {
    expect(
      npmAuthInEnv({
        GITHUB_TOKEN: "ghs_x",
        ACTIONS_ID_TOKEN_REQUEST_TOKEN: "x",
        ACTIONS_ID_TOKEN_REQUEST_URL: "https://example",
        NPM_TOKEN: "",
        NODE_AUTH_TOKEN: undefined,
        npm_config_registry: "https://registry.npmjs.org/",
        npm_config_always_auth: "true", // a boolean, not a credential
      }),
    ).toEqual([]);
  });
});

describe("npmrcHasAuth", () => {
  test("finds a credential, scoped or not, literal or a reference", () => {
    expect(npmrcHasAuth("//registry.npmjs.org/:_authToken=npm_abc\n")).toBe(true);
    expect(npmrcHasAuth("registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=${NPM_TOKEN}\r\n")).toBe(true);
    expect(npmrcHasAuth("_auth = dXNlcjpwYXNz")).toBe(true);
    expect(npmrcHasAuth("//npm.example/:_password=cGFzcw==")).toBe(true);
  });

  test("passes a file with no credential, or one only in a comment", () => {
    expect(npmrcHasAuth("")).toBe(false);
    expect(npmrcHasAuth("@kashscript:registry=https://registry.npmjs.org/\nsave-exact=true\n")).toBe(false);
    expect(npmrcHasAuth("# //registry.npmjs.org/:_authToken=old\n; _auth=old\n")).toBe(false);
    expect(npmrcHasAuth("always-auth=true")).toBe(false);
  });
});

describe("oidcClaims and provenanceVerdict", () => {
  test("reads the claims GitHub puts in the token", () => {
    const c = oidcClaims(
      jwt({
        repository: "KashShahzad/kashscript",
        repository_visibility: "private",
        ref: "refs/heads/rw-2",
        environment: "npm-publish",
        workflow_ref: "KashShahzad/kashscript/.github/workflows/publish.yml@refs/heads/rw-2",
        aud: "npm:registry.npmjs.org",
      }),
    );
    expect(c).toEqual({
      repository: "KashShahzad/kashscript",
      repository_visibility: "private",
      ref: "refs/heads/rw-2",
      environment: "npm-publish",
      workflow_ref: "KashShahzad/kashscript/.github/workflows/publish.yml@refs/heads/rw-2",
    });
  });

  test("refuses a malformed token", () => {
    expect(() => oidcClaims("not-a-jwt")).toThrow("not a JWT");
  });

  test("a private repository cannot carry provenance — the stated reason", () => {
    const v = provenanceVerdict({ repository: "KashShahzad/kashscript", repository_visibility: "private" });
    expect(v.ok).toBe(false);
    if (!v.ok) {
      expect(v.reason).toStartWith("provenance impossible: KashShahzad/kashscript is private");
      expect(v.reason).toContain("a real publish refuses");
    }
  });

  test("a missing claim is refused, not assumed public", () => {
    expect(provenanceVerdict({}).ok).toBe(false);
  });

  test("a public repository passes", () => {
    expect(provenanceVerdict({ repository: "KashShahzad/kashscript", repository_visibility: "public" })).toEqual({ ok: true });
  });
});

describe("exchangeOutcome", () => {
  test("a token back means npmjs.com has the trusted publisher", () => {
    expect(exchangeOutcome(201, { token: "short-lived" })).toEqual({ configured: true });
  });

  test("anything else is not configured, with npm's message", () => {
    expect(exchangeOutcome(404, { message: "No trusted publisher configured for this package" })).toEqual({
      configured: false,
      reason: "HTTP 404: No trusted publisher configured for this package",
    });
    expect(exchangeOutcome(401, { error: "invalid token" })).toEqual({ configured: false, reason: "HTTP 401: invalid token" });
    expect(exchangeOutcome(500, "oops")).toEqual({ configured: false, reason: "HTTP 500" });
    expect(exchangeOutcome(200, {})).toEqual({ configured: false, reason: "HTTP 200" });
  });
});

test("escapedName matches npm-package-arg", () => {
  expect(escapedName("@kashscript/terms")).toBe("@kashscript%2fterms");
  expect(escapedName("fflate")).toBe("fflate");
});

describe("repositoryVerdict (AU-11): npm refuses provenance whose repository.url names another repository", () => {
  const field = { type: "git", url: "git+https://github.com/KashShahzad/kashscript.git", directory: "packages/terms" };

  test("the field the open packages carry passes for the public repository, case-insensitively", () => {
    expect(repositoryVerdict(field, "KashShahzad/kashscript", "terms")).toEqual({ ok: true });
    expect(repositoryVerdict(field, "kashshahzad/KASHSCRIPT", "terms")).toEqual({ ok: true });
  });

  test("a missing field, another repository, or another directory refuses with the reason", () => {
    const missing = repositoryVerdict(undefined, "KashShahzad/kashscript", "terms");
    expect(missing.ok).toBe(false);
    if (!missing.ok) expect(missing.reason).toContain("no repository.url");

    const other = repositoryVerdict({ ...field, url: "https://github.com/kashscript/kashscript.git" }, "KashShahzad/kashscript", "terms");
    expect(other.ok).toBe(false);
    if (!other.ok) expect(other.reason).toContain("kashscript/kashscript");

    const archive = repositoryVerdict(field, "KashShahzad/kashscript-archive", "terms");
    expect(archive.ok).toBe(false);

    const dir = repositoryVerdict(field, "KashShahzad/kashscript", "kash");
    expect(dir.ok).toBe(false);
    if (!dir.ok) expect(dir.reason).toContain('"packages/kash"');

    expect(repositoryVerdict(field, undefined, "terms").ok).toBe(false);
  });

  test("githubRepoOf reads the URL forms npm accepts and nothing else", () => {
    expect(githubRepoOf("git+https://github.com/KashShahzad/kashscript.git")).toBe("kashshahzad/kashscript");
    expect(githubRepoOf("https://github.com/KashShahzad/kashscript")).toBe("kashshahzad/kashscript");
    expect(githubRepoOf("git://github.com/a/b.git")).toBe("a/b");
    expect(githubRepoOf("git+ssh://git@github.com/a/b.git")).toBe("a/b");
    expect(githubRepoOf("https://gitlab.com/a/b.git")).toBeUndefined();
    expect(githubRepoOf("https://github.com/a/b/tree/main")).toBeUndefined();
  });
});
