// ============================================================================
// The holder export through the published CLI, under plain Node, with the
// network switched off (specs/holder-contract.md §2 — "verifiable offline").
// ----------------------------------------------------------------------------
// `offline-guard.cjs` makes fetch, net, tls, dns, http, https, http2 and dgram
// throw. A PASS under it is a PASS from the file alone. The one flag allowed
// to reach the network, --check-status, is shown to be exactly that.
// ============================================================================

import { describe, it, expect, beforeAll } from "bun:test";
import { spawnSync } from "node:child_process";
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const PKG = join(import.meta.dir, "..");
const WIN = process.platform === "win32";
const BIN = "dist/bin/attest.js";
const GUARD = "./test/offline-guard.cjs";
const EXPORT = "test/vectors/holder/holder-export.v1.json";
const PUBLISHER = "did:kash:CJyXiKAaH3EeBHm4ympbXJPBNE4JoTuA4QYVvRS5u3CT";

function runNode(args: readonly string[]): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync("node", args, { cwd: PKG, encoding: "utf8", shell: WIN });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

beforeAll(() => {
  const build = spawnSync("bun", ["run", "build:bin"], { cwd: PKG, encoding: "utf8", shell: WIN });
  if (build.status !== 0) throw new Error(`build:bin failed:\n${build.stderr || build.stdout}`);
});

describe("attest bin — a holder export, verified with the network disabled", () => {
  it("the guard really does disable the network", () => {
    const probe = join(tmpdir(), `attest-offline-probe-${process.pid}.cjs`);
    writeFileSync(
      probe,
      "let n = 0;\n" +
        "for (const f of [() => fetch('https://example.org'), () => require('https').get('https://example.org'), () => require('dns').lookup('example.org', () => {}), () => require('net').connect(443, 'example.org')]) {\n" +
        "  try { f(); } catch (e) { if (String(e.message).includes('offline-guard')) n++; }\n" +
        "}\n" +
        "console.log('refused ' + n);\n",
    );
    try {
      const r = runNode(["--require", GUARD, probe]);
      expect(r.stdout).toContain("refused 4");
    } finally {
      rmSync(probe, { force: true });
    }
  });

  it("passes (exit 0) under the guard, with no key on the command line", () => {
    const r = runNode(["--require", GUARD, BIN, "verify", EXPORT, "--trust-publisher", PUBLISHER]);
    expect(r.stderr).not.toContain("offline-guard");
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("network            : none");
    expect(r.stdout).toContain("canonical bytes    : yes");
    expect(r.stdout).toContain("RESULT: PASS");
  });

  it("states status with its time, and never calls an unlisted issuer listed", () => {
    const r = runNode(["--require", GUARD, BIN, "verify", EXPORT, "--trust-publisher", PUBLISHER]);
    expect(r.stdout).toContain("valid unless revoked, as of 2026-09-23T00:00:00Z");
    expect(r.stdout).toContain("acme/bench/doer-7 — UNLISTED");
    expect(r.stdout).toContain("device-asserted — the holder's own device; never countersigned");
    expect(r.stdout).not.toMatch(/trusted/i);
  });

  it("without a pinned publisher, nothing is shown as listed — and the file still verifies", () => {
    const r = runNode(["--require", GUARD, BIN, "verify", EXPORT]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("NOT pinned");
    expect(r.stdout).not.toContain("— listed (");
  });

  it("verifies the trust list and the status list on their own", () => {
    const t = runNode(["--require", GUARD, BIN, "verify", "test/vectors/holder/trust-list.v1.json", "--trust-publisher", PUBLISHER]);
    expect(t.status).toBe(0);
    expect(t.stdout).toContain("pinned");
    const s = runNode(["--require", GUARD, BIN, "verify", "test/vectors/holder/status-list.v1.json"]);
    expect(s.status).toBe(0);
    expect(s.stdout).toContain("entries            : 131072");
  });

  it("--check-status is the only path that reaches for the network", () => {
    const e = JSON.parse(readFileSync(join(PKG, EXPORT), "utf8")) as { statusLists: unknown[] };
    e.statusLists = [];
    const path = join(tmpdir(), `attest-holder-nolist-${process.pid}.json`);
    writeFileSync(path, JSON.stringify(e));
    try {
      const quiet = runNode(["--require", GUARD, BIN, "verify", path, "--trust-publisher", PUBLISHER]);
      expect(quiet.stdout).not.toContain("offline-guard");
      expect(quiet.stdout).toContain("status not checked");
      const asked = runNode(["--require", GUARD, BIN, "verify", path, "--trust-publisher", PUBLISHER, "--check-status"]);
      expect(asked.stdout).toContain("offline-guard: fetch is disabled");
    } finally {
      rmSync(path, { force: true });
    }
  });

  it("fails a record whose manifest claims more than its bytes (exit 1)", () => {
    const e = JSON.parse(readFileSync(join(PKG, EXPORT), "utf8")) as { records: { manifest: { type: { tag: string; attestation: string } } }[] };
    for (const r of e.records) if (r.manifest.type.tag === "indus.poe.v1.geo") r.manifest.type.attestation = "countersigned";
    const path = join(tmpdir(), `attest-holder-forged-${process.pid}.json`);
    writeFileSync(path, JSON.stringify(e));
    try {
      const r = runNode(["--require", GUARD, BIN, "verify", path, "--trust-publisher", PUBLISHER]);
      expect(r.status).toBe(1);
      expect(r.stdout).toContain("MANIFEST_CLASS_MISMATCH");
      expect(r.stdout).toContain("RESULT: FAIL");
    } finally {
      rmSync(path, { force: true });
    }
  });
});
