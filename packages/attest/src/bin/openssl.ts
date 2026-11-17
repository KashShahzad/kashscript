/**
 * The RFC 3161 signature check, done by `openssl ts -verify` against a root the
 * caller names (KS-Q4) — the same call GOV-5's `anchors/anchor.py` makes for the
 * decision log. attest reads a token's digest and time itself; the CMS
 * signature and its X.509 chain are openssl's, judged as of the token's own time.
 *
 * Node only (the CLI); the library never spawns anything. `openssl` loads the
 * system's trust store unless told otherwise, so the named root is given as
 * the CA file AND the CA store, and the CA path is an empty folder: the root
 * the caller named is the only trust anchor.
 */

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readRfc3161Token } from "../witness/rfc3161";
import type { Rfc3161SignatureCheck } from "../witness/verdict";

const slash = (p: string): string => p.replace(/\\/g, "/");

/** SHA-256 of a PEM certificate's DER, hex — what to compare with an authority's published fingerprint. */
export function pemFingerprint(pem: string): string {
  const b64 = pem.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+/g, "");
  return createHash("sha256").update(Buffer.from(b64, "base64")).digest("hex");
}

/** Is `openssl` on this machine? */
export function opensslAvailable(): boolean {
  const p = spawnSync("openssl", ["version"], { encoding: "utf8" });
  return p.error === undefined && p.status === 0;
}

export interface OpensslCheck {
  readonly check: Rfc3161SignatureCheck;
  /** The root's fingerprint, to print beside every verdict that rests on it. */
  readonly rootSha256: string;
}

/** A signature check that trusts exactly the root in `rootPemPath`. Throws if the file is not a certificate. */
export function opensslRfc3161Check(rootPemPath: string): OpensslCheck {
  const pem = readFileSync(rootPemPath, "utf8");
  if (!pem.includes("-----BEGIN CERTIFICATE-----")) throw new Error(`${rootPemPath} is not a PEM certificate`);
  const root = slash(rootPemPath);
  return {
    rootSha256: pemFingerprint(pem),
    async check(tsr, digestHex) {
      if (!/^[0-9a-f]{64}$/.test(digestHex)) return false;
      const token = await readRfc3161Token(tsr).catch(() => null);
      if (token === null) return false;
      const work = mkdtempSync(join(tmpdir(), "attest-tsr-"));
      const empty = mkdtempSync(join(tmpdir(), "attest-capath-"));
      try {
        const file = join(work, "token.tsr");
        writeFileSync(file, tsr);
        const p = spawnSync(
          "openssl",
          ["ts", "-verify", "-digest", digestHex, "-in", slash(file), "-CAfile", root, "-CApath", slash(empty), "-CAstore", root, "-attime", String(token.genTimeUnix)],
          { encoding: "utf8" },
        );
        return p.error === undefined && p.status === 0 && /Verification: OK/.test(`${p.stdout}${p.stderr}`);
      } finally {
        rmSync(work, { recursive: true, force: true });
        rmSync(empty, { recursive: true, force: true });
      }
    },
  };
}
