/**
 * The must-nots, as tests: no score, percentage or ranking anywhere a person
 * is described; routing never refuses; nothing in the evaluator reads a clock,
 * a network or a model; the registered types stay in step with attest.
 */

import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { lookupDst } from "@kashscript/attest/dst";
import { checklist } from "../src/checklist";
import { buildPacket, checkPacket, type PacketEntry } from "../src/packet";
import { route, type Route } from "../src/route";
import { ruleRequest } from "../src/rule";
import { DECISION_VCT, OWN_WORD_VCT, RULE_PAYLOAD_TYPE } from "../src/constants";
import { AS_OF, englishCert, hiringWorld, party, T0 } from "./world";

/** Every number in a value, with where it is — except where a number is a version or a window in days. */
function numbersIn(v: unknown, path = "$", out: string[] = []): string[] {
  if (typeof v === "number") out.push(path);
  else if (Array.isArray(v)) v.forEach((x, i) => numbersIn(x, `${path}[${i}]`, out));
  else if (typeof v === "object" && v !== null) for (const [k, x] of Object.entries(v)) if (k !== "version" && k !== "contestWithinDays") numbersIn(x, `${path}.${k}`, out);
  return out;
}
const SCOREISH = /score|percent|rank|rating|grade|progress|ratio/i;
function keysIn(v: unknown, out: string[] = []): string[] {
  if (Array.isArray(v)) v.forEach((x) => keysIn(x, out));
  else if (typeof v === "object" && v !== null) for (const [k, x] of Object.entries(v)) {
    out.push(k);
    keysIn(x, out);
  }
  return out;
}

describe("no score, percentage or ranking — the checklist and the route carry no number", async () => {
  const w = await hiringWorld();
  const copy = await party();
  const cert = await englishCert(w.assessor, copy);
  const held = [...w.projects.map((v, i) => ({ ref: `p${i}`, value: v })), { ref: "cert", value: cert }];
  const partial = [{ ref: "p0", value: w.projects[0] }];

  test("checklists, full and partial", async () => {
    for (const h of [held, partial, []]) {
      const list = await checklist(w.rule, h, { asOf: AS_OF, trustLists: [w.list], ownWord: { availability: { availableFrom: "2026-11-15" } } });
      expect(numbersIn(list)).toEqual([]);
      expect(keysIn(list).filter((k) => SCOREISH.test(k))).toEqual([]);
    }
  });

  test("routes, for every outcome — and no route is ever a refusal", async () => {
    const req = ruleRequest(w.rule, { nonce: "guard-nonce-0123456789", responseUri: "https://door.practice.invalid/a" });
    const word: PacketEntry = { kind: "own-word", queryId: "availability_word", fields: { availableFrom: "2026-11-15" }, signer: await party() };
    const artifacts = (n: number) => w.projects.slice(0, n).map((a): PacketEntry => ({ kind: "artifact", queryId: "projects", artifact: a as unknown as Record<string, unknown>, signer: w.doer }));
    const seen = new Set<Route>();
    for (const entries of [[...artifacts(3), { kind: "sd-jwt", queryId: "english", held: cert, signer: copy } as PacketEntry, word], artifacts(1), []]) {
      const packet = await buildPacket({ rule: w.rule, request: req, entries, iatUnix: T0 });
      const check = await checkPacket({ rule: w.rule, request: req, vp_token: packet.vp_token, ctx: { trustLists: [w.list] }, asOf: AS_OF });
      for (const askedForPerson of [false, true]) {
        const r = await route(w.rule, check, { asOf: AS_OF, askedForPerson });
        seen.add(r.route);
        expect(["automatic-yes", "not-yet", "to-a-person"]).toContain(r.route);
        expect(numbersIn({ rows: r.rows, fired: r.fired, missing: r.missing, unread: r.unread, reasons: r.reasons, why: r.why })).toEqual([]);
        expect(keysIn(r).filter((k) => SCOREISH.test(k))).toEqual([]);
      }
    }
    expect([...seen].sort()).toEqual(["automatic-yes", "not-yet", "to-a-person"]);
  });
});

describe("the route's type has no refusal in it", () => {
  test("Route is exactly the three", () => {
    type Refusing = Extract<Route, "no" | "partial" | "refuse" | "refused" | "reject">;
    const none: [Refusing] extends [never] ? true : false = true;
    expect(none).toBe(true);
  });
});

describe("no clock, no randomness, no network, no model in the evaluator", () => {
  const SRC = join(import.meta.dir, "..", "src");
  const files = (dir: string): string[] => readdirSync(dir).flatMap((f) => (statSync(join(dir, f)).isDirectory() ? files(join(dir, f)) : f.endsWith(".ts") ? [join(dir, f)] : []));
  const evaluator = files(SRC).filter((f) => !/packet\.ts$|decision\.ts$|fixtures/.test(f));
  test("pure files read no clock, no randomness and no network", () => {
    for (const f of evaluator) {
      const text = readFileSync(f, "utf8").replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, "");
      for (const banned of [/Date\.now\s*\(/, /new Date\(\s*\)/, /Math\.random/, /getRandomValues/, /\bfetch\s*\(/, /XMLHttpRequest/, /WebSocket/, /process\.env/]) {
        expect(`${f}: ${banned.test(text)}`).toBe(`${f}: false`);
      }
    }
  });
  test("the package imports only the kernel — no model, no runtime for one", () => {
    for (const f of files(SRC)) {
      for (const m of readFileSync(f, "utf8").matchAll(/from\s+"([^"]+)"/g)) {
        const spec = m[1]!;
        expect(spec.startsWith(".") || ["@kashscript/attest", "@kashscript/identity-core", "@kashscript/lexicons"].some((p) => spec === p || spec.startsWith(`${p}/`))).toBe(true);
      }
    }
    const pkg = JSON.parse(readFileSync(join(import.meta.dir, "..", "package.json"), "utf8")) as { dependencies: Record<string, string> };
    expect(Object.keys(pkg.dependencies).sort()).toEqual(["@kashscript/attest", "@kashscript/identity-core", "@kashscript/lexicons"]);
  });
});

describe("the registered types stay in step with attest", () => {
  test("rule, decision and own word", () => {
    expect(lookupDst(RULE_PAYLOAD_TYPE)?.family).toBe("dsse-type");
    expect(lookupDst(DECISION_VCT)?.family).toBe("sd-jwt-vct");
    expect(lookupDst(OWN_WORD_VCT)?.family).toBe("sd-jwt-vct");
    for (const t of [RULE_PAYLOAD_TYPE, DECISION_VCT, OWN_WORD_VCT]) expect(lookupDst(t)?.owner).toBe("@kashscript/predicate");
  });
});
