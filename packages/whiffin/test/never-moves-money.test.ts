// KS-R4 — whiffin is the mandate protocol and it never moves money. These are
// the rules of that sentence, kept true by a test rather than by a habit:
//   1. no settle path, no custody state, no partner ledger anywhere in src/;
//   2. no I/O that could reach a rail — no network, no process, no filesystem;
//   3. the public surface exposes no function that pays, settles, refunds or
//      marks a payment done.
// (This file lives in test/, outside the src/ it reads.)

import { describe, expect, it } from "bun:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

import * as whiffin from "../src";

const SRC = join(import.meta.dir, "..", "src");

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    return statSync(full).isDirectory() ? sourceFiles(full) : full.endsWith(".ts") ? [full] : [];
  });
}

function hits(pattern: RegExp): string[] {
  const out: string[] = [];
  for (const file of sourceFiles(SRC)) {
    readFileSync(file, "utf-8").split("\n").forEach((line, i) => {
      if (pattern.test(line)) out.push(`${file.slice(SRC.length + 1)}:${i + 1}: ${line.trim()}`);
    });
  }
  return out;
}

describe("whiffin never moves money", () => {
  it("src/ has no settle path and no custody vocabulary", () => {
    expect(hits(/settle/i)).toEqual([]);
    expect(hits(/clawback|claw back|trustAccount|partner-?ledger|escrow/i)).toEqual([]);
  });

  it("src/ makes no network, process or filesystem call (it cannot reach a rail)", () => {
    expect(hits(/\bfetch\s*\(|XMLHttpRequest|WebSocket|EventSource|node:(http|https|net|tls|dgram|child_process|fs|dns)/)).toEqual([]);
  });

  it("the public surface has no function that pays, settles, refunds or marks a payment done", () => {
    const names = Object.entries(whiffin).filter(([, v]) => typeof v === "function").map(([k]) => k);
    expect(names.length).toBeGreaterThan(5); // the surface was really enumerated
    expect(names.filter((n) => /pay|settle|refund|transfer|send|disburse|mark.*(paid|done|complete)/i.test(n))).toEqual([]);
  });

  it("the package version and the lifecycle moved together (0.2.0)", () => {
    expect(whiffin.WHIFFIN_VERSION).toBe("0.2.0");
    expect([...whiffin.GRANT_LIFECYCLE_STATES]).toEqual(["ISSUED", "DELIVERED", "REDEEMED", "EXPIRED"]);
  });
});
