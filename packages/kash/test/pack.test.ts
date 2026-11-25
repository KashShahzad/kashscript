/**
 * PY-8 — set-up packs (`kashscript-pack/1`):
 *   - `kash pack build` checks a pack offline against `@kashscript/predicate` and `@kashscript/floor` (RW-17),
 *     refuses any price, percentage, internal word (`studio`, `foundry`, `workshop`), never-word, unlabelled or
 *     non-null node-descriptor slot (ADR-0029), undeclared route, waiver, or floor violation;
 *   - both `bunSrc` and `nodeDist` (plain Node under `offline-guard.cjs`) build and list packs with zero network;
 *   - `kash pack install <dir> --host <url>` refuses a non-practice server (`NOT_PRACTICE_HOST`), installs on a
 *     clean practice organisation in one command, completes the first approval, and produces a record that
 *     `kash verify` checks offline (`RESULT: PASS`, exit 0);
 *   - when the workspace archive holds `packs/*` and the sibling `Duedale 2.0` engine is present on disk, all
 *     three real packs (`client-sign-off`, `internships-that-count`, `host-receipts`) install end to end against
 *     the real Duedale practice host and pass `kash verify` offline.
 */

import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { join, resolve } from "node:path";

import { canonicalizeBytes, deriveDid, generateKeyPair } from "@kashscript/identity-core";
import {
  bytesToBase64,
  bytesToBase64Url,
  ulid,
  type CountersignBundle,
  type DsseEnvelope,
  type SignedCountersignAcceptance,
  type SignedCountersignRequest,
} from "@kashscript/attest";
import {
  acceptCountersignRequest,
  assembleCountersignBundle,
  createCountersignRequest,
} from "@kashscript/identity-server";
import { ruleHash, type RuleBody } from "@kashscript/predicate";

import { practiceOrgSlug } from "../src/pack";
import { buildBundles, bunSrc, nodeDist, PKG, removeDir, tempDir, type Runner } from "./helpers";

// Set here, not only in helpers.ts: a test here starts up to eight `kash pack build` processes, each loading the
// TypeScript compiler for the floor check, and helpers.ts's own default reaches only the first file that loads it in a
// run. In a fresh export of the public tree these tests ran past Bun's 5s default (2026-11-26).
setDefaultTimeout(60_000);

const REPO_ROOT = resolve(PKG, "..", "..");
const PACKS_ROOT = join(REPO_ROOT, "packs");
const DUEDALE_HOST_DIR = resolve(REPO_ROOT, "..", "Duedale 2.0", "apps", "duedale-core-host");
const HAS_ARCHIVE_PACKS =
  existsSync(join(PACKS_ROOT, "client-sign-off", "pack.json")) &&
  existsSync(join(PACKS_ROOT, "internships-that-count", "pack.json")) &&
  existsSync(join(PACKS_ROOT, "host-receipts", "pack.json"));
const HAS_DUEDALE_HOST = existsSync(join(DUEDALE_HOST_DIR, "scripts", "e2e-server.ts"));

const RUNNERS: ReadonlyArray<readonly [string, Runner]> = [
  ["bun-src", bunSrc],
  ["node-dist", nodeDist],
];

const SAMPLE_STATEMENT =
  "I accept this milestone as delivered against the scope we agreed. Signing records my acceptance of this milestone only; it does not approve any other milestone, invoice, or payment.";

/** Why a pack's floor manifest declares a route no oracle of the pack sees: the engine serves it, the pack mounts nothing. */
const ENGINE_ROUTE = "served by Duedale's API; a pack mounts no route";

async function writeValidFixturePack(dir: string, slug = "fixture-sign-off"): Promise<{ dir: string; ruleSha256: string }> {
  mkdirSync(dir, { recursive: true });
  const rule: RuleBody = {
    id: `did:kash:PracticeAuthorDidSwapAtSetup11111111/rule/${slug}`,
    version: 1,
    author: "did:kash:PracticeAuthorDidSwapAtSetup11111111",
    title: "Practice sign-off rule (sample, v1)",
    purpose: "A buyer checks whether an agency presents client-accepted milestone records under versioned scopes.",
    visibility: "public",
    parameters: {
      minAcceptedMilestones: {
        type: "number",
        value: 1,
        bounds: { min: 1, max: 10 },
      },
    },
    dates: {
      published: "2026-11-26T00:00:00Z",
      renewBy: "2027-10-26T00:00:00Z",
      endsAt: "2027-11-26T00:00:00Z",
    },
    decider: { role: "Procurement reviewer at the buyer" },
    outcome: {
      grants: "Confirms that the agency presented accepted milestone records meeting the stated minimum.",
      binds: false,
      sensitive: false,
      automaticYes: true,
    },
    reasons: [
      { code: "milestones-shown", outcome: "yes", text: "The presented records show the required accepted milestones." },
      { code: "milestones-missing", outcome: "not-yet", text: "Fewer accepted milestones were presented than asked for." },
      { code: "not-matched", outcome: "no", text: "A named person at the buyer gives reasons in writing." },
    ],
    contest: {
      windowDays: 30,
      answerDays: 14,
      how: "Reply to the decision receipt; a person who did not decide first answers in writing.",
    },
    anotherWay: "Written acceptance letters read by a person.",
    address: {
      sector: { classification: "ISIC", revision: "5", code: "62" },
      anchorFamily: "work",
      authority: { kind: "institution", name: "Practice procurement desk (sample)" },
      journey: "earn-and-spend",
      givens: {
        area: { text: "Online and across borders.", anywhere: true },
        spaces: { text: "Each organisation's workplace and online.", kinds: ["workplace", "online"] },
        capitals: {
          text: "A named reviewer at the buyer and the agency's book on Duedale.",
          needs: [
            { kind: "people", what: "A named reviewer at the buyer" },
            { kind: "systems", what: "The agency's book on Duedale" },
          ],
        },
        culture: {
          text: "Judged by accepted deliverables under an agreed scope.",
          codes: [{ title: "Agreed statement of work" }],
          languages: ["en"],
        },
        economy: { text: "Services between organisations.", level: "tertiary" },
        time: { text: "Per milestone; renewed yearly.", renews: "P1Y" },
        relations: { text: "Agency to client on each milestone." },
      },
    },
    criteria: [
      {
        id: "accepted-milestones",
        subject: "organisation",
        label: "Client-accepted milestone records",
        purpose: "Shows that an outside client countersigned the agency's delivered milestones.",
        answer: {
          by: "receipts",
          query: [
            {
              id: "accepted-milestones",
              multiple: true,
              format: "kash-artifact",
              meta: {
                dst_values: ["application/vnd.oreoasis.work-record+json"],
                attestation: "countersigned",
              },
              claims: [
                { id: "shape", path: ["shape"], values: ["accepted"] },
                { id: "scopeVersion", path: ["rule", "version"] },
              ],
            },
          ],
        },
        condition: {
          feel: "count(receipts) >= minAcceptedMilestones",
          types: {
            shape: "string",
            scopeVersion: "string",
          },
        },
      },
    ],
    practice: true,
  };
  const rHash = await ruleHash(rule);

  writeFileSync(
    join(dir, "pack.json"),
    JSON.stringify(
      {
        format: "kashscript-pack/1",
        slug,
        title: "Practice Sign-off",
        forWhom: "An agency delivering scoped milestones",
        summary: "Milestone sign-off on a link, countersigned by the client.",
        cycle: "Each milestone delivery and client acceptance",
        descriptor: {
          node: null,
          label: "Empty until the one-engine merge specifies a kernel node descriptor (ADR-0029); OpenID4VCI metadata serves today.",
        },
        files: {
          rule: "rule.json",
          ruleDoc: "rule.md",
          acceptance: "acceptance.json",
          screens: "screens.json",
          checklist: "checklist.md",
          scope: "scope.json",
          buyerSupplies: "buyer-supplies.json",
          floor: "floor.manifest.json",
        },
      },
      null,
      2,
    ),
    "utf8",
  );
  writeFileSync(join(dir, "rule.json"), JSON.stringify(rule, null, 2), "utf8");
  writeFileSync(
    join(dir, "rule.md"),
    [
      "# Practice Sign-off — open rule (sample, v1)",
      "",
      `- **SHA-256 (JCS):** \`${rHash}\``,
      "- **Licence:** Released under CC BY 4.0.",
      "",
    ].join("\n"),
    "utf8",
  );
  writeFileSync(
    join(dir, "acceptance.json"),
    JSON.stringify(
      {
        statement: SAMPLE_STATEMENT,
        whoApproves: "The named client reviewer on an approval link.",
        whatApprovingSays: "That this milestone meets what done means under the agreed scope.",
        doesNotProve: [
          "Does not approve any other milestone or change of scope.",
          "Does not prove that an invoice was settled.",
        ],
        whenNotReady: "Close the page without signing; nothing declined is published.",
      },
      null,
      2,
    ),
    "utf8",
  );
  writeFileSync(
    join(dir, "screens.json"),
    JSON.stringify(
      {
        engine: "duedale",
        apiVersion: "v1",
        selfHostPath: "Run your own Duedale host and pass --host https://your-host.example.",
        flow: "client-sign-off",
        recordProfile: "oreoasis-milestone/2",
        screens: [
          {
            id: "approval-link",
            title: "Approval on a link",
            audience: "approver",
            route: "PAGE /approve",
            shows: ["The milestone title, what done means, and the exact acceptance words."],
            neverShows: ["Any account sign-up wall or personal score."],
          },
        ],
        apiRoutes: [
          "POST /api/v1/engagements",
          "POST /api/v1/engagements/:id/milestones/:mid/deliver",
          "POST /api/v1/acceptances",
          "GET /api/v1/verify/:receiptNo/bundle",
        ],
        practice: {
          engagement: {
            clientLabel: "Practice Client (Simulation)",
            scopeText: "Deliver one milestone under a written scope (practice simulation).",
            scopeDays: 30,
            milestoneTitle: "Milestone 1 — Practice hand-off",
            doneMeans: "Hand-off notes read and accepted in practice.",
            stack: ["TypeScript"],
          },
        },
      },
      null,
      2,
    ),
    "utf8",
  );
  writeFileSync(
    join(dir, "checklist.md"),
    [
      "# Set-up checklist",
      "",
      "1. Confirm the organisation name and slug.",
      "2. Enter the first engagement scope and milestone.",
      "3. Complete one practice approval and verify the downloaded bundle offline.",
      "",
    ].join("\n"),
    "utf8",
  );
  writeFileSync(
    join(dir, "scope.json"),
    JSON.stringify(
      {
        inScope: [
          "Provisioning the organisation book and issuer metadata.",
          "Walking through the first milestone delivery and offline verification.",
        ],
        outOfScope: [
          "Contract drafting or legal advice.",
          "Invoicing or payment collection.",
        ],
        neverDoes: [
          "Never charges per milestone or per verification.",
          "Never publishes a declined milestone or ranks people.",
          "Never locks the organisation to one host.",
        ],
        fittingTerms: "Fixed-scope fitting labour; the rule is open under CC BY 4.0 and self-hosting is always supported.",
      },
      null,
      2,
    ),
    "utf8",
  );
  writeFileSync(
    join(dir, "buyer-supplies.json"),
    JSON.stringify(
      {
        items: [
          {
            id: "org-identity",
            label: "Organisation display name and slug",
            why: "Used to mint the organisation's signing key.",
            format: "Plain text name and lowercase hyphenated slug.",
          },
        ],
      },
      null,
      2,
    ),
    "utf8",
  );
  writeFileSync(
    join(dir, "floor.manifest.json"),
    JSON.stringify(
      {
        // The floor's own format (RW-17, `packages/floor/README.md`): a pack mounts nothing, so every route is the
        // engine's, declared with its subject and shape and `outsideOracle` saying why no oracle of the pack sees it.
        floor: 1,
        repository: `pack:${slug}`,
        serves: "none",
        routes: {
          "PAGE /approve": { subject: "record", shape: "action", outsideOracle: ENGINE_ROUTE },
          "POST /api/v1/engagements": { subject: "organisation", shape: "action", outsideOracle: ENGINE_ROUTE },
          "POST /api/v1/engagements/:id/milestones/:mid/deliver": { subject: "record", shape: "action", outsideOracle: ENGINE_ROUTE },
          "POST /api/v1/acceptances": { subject: "record", shape: "action", outsideOracle: ENGINE_ROUTE },
          "GET /api/v1/verify/:receiptNo/bundle": { subject: "record", shape: "presented", outsideOracle: ENGINE_ROUTE },
        },
      },
      null,
      2,
    ),
    "utf8",
  );
  return { dir, ruleSha256: rHash };
}

async function freeLoopbackPort(): Promise<number> {
  return await new Promise<number>((resolvePort, reject) => {
    const srv = createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      const port = typeof addr === "object" && addr !== null ? addr.port : 0;
      srv.close((err) => (err ? reject(err) : resolvePort(port)));
    });
  });
}

describe("PY-8 set-up packs — offline build, floor gate, and copy/price refusals", () => {
  const roots: string[] = [];
  const mk = (label: string): string => {
    const d = tempDir(label);
    roots.push(d);
    return d;
  };

  beforeAll(() => {
    buildBundles();
  });

  afterAll(() => {
    for (const d of roots) removeDir(d);
  });

  for (const [name, run] of RUNNERS) {
    it(`[${name}] builds and lists a clean pack offline, keeping the node-descriptor slot null and labelled`, async () => {
      const parent = mk(`pack-ok-${name}`);
      const packDir = join(parent, "fixture-sign-off");
      const { ruleSha256 } = await writeValidFixturePack(packDir);

      const built = run(["pack", "build", packDir, "--json"]);
      expect(built.status).toBe(0);
      const parsed = JSON.parse(built.stdout);
      expect(parsed.format).toBe("kashscript-pack/1");
      expect(parsed.slug).toBe("fixture-sign-off");
      expect(parsed.descriptor.node).toBeNull();
      expect(parsed.descriptor.label).toContain("ADR-0029");
      expect(parsed.rule.sha256).toBe(ruleSha256);
      expect(parsed.floor).toEqual({ ok: true, routesChecked: 5 });

      const listed = run(["pack", "list", parent, "--json"]);
      expect(listed.status).toBe(0);
      const listParsed = JSON.parse(listed.stdout);
      expect(listParsed).toHaveLength(1);
      expect(listParsed[0].slug).toBe("fixture-sign-off");
    });
  }

  if (HAS_ARCHIVE_PACKS) {
    for (const [name, run] of RUNNERS) {
      it(`[${name}] builds all three real packs in packs/ offline with zero prices, zero internal words, and green floor`, () => {
        const res = run(["pack", "list", PACKS_ROOT, "--json"]);
        expect(res.status).toBe(0);
        const packs = JSON.parse(res.stdout) as Array<{
          slug: string;
          flow: string;
          descriptor: { node: unknown; label: string };
          floor: { ok: boolean; routesChecked: number };
        }>;
        expect(packs.map((p) => p.slug)).toEqual([
          "client-sign-off",
          "host-receipts",
          "internships-that-count",
        ]);
        for (const p of packs) {
          expect(p.descriptor.node).toBeNull();
          expect(p.descriptor.label.length).toBeGreaterThan(10);
          expect(p.floor.ok).toBe(true);
          expect(p.floor.routesChecked).toBeGreaterThanOrEqual(5);
        }
      });
    }
  }

  it("refuses any price field, currency figure, or percentage anywhere in a pack", async () => {
    // 1. Price key in scope.json
    const d1 = mk("pack-price-key");
    await writeValidFixturePack(d1);
    const scope = JSON.parse(readFileSync(join(d1, "scope.json"), "utf8"));
    scope.setupFee = "flat";
    writeFileSync(join(d1, "scope.json"), JSON.stringify(scope, null, 2), "utf8");
    const r1 = bunSrc(["pack", "build", d1]);
    expect(r1.status).toBe(1);
    expect(r1.stderr).toMatch(/price, fee, currency or percentage/i);

    // 2. Currency figure in checklist.md
    const d2 = mk("pack-price-cur");
    await writeValidFixturePack(d2);
    writeFileSync(join(d2, "checklist.md"), "1. Confirm the USD 500 set-up scope.\n", "utf8");
    const r2 = bunSrc(["pack", "build", d2]);
    expect(r2.status).toBe(1);
    expect(r2.stderr).toContain("USD 500");

    // 3. Percentage in acceptance.json
    const d3 = mk("pack-price-pct");
    await writeValidFixturePack(d3);
    const acc = JSON.parse(readFileSync(join(d3, "acceptance.json"), "utf8"));
    acc.whatApprovingSays = "Releases 50% of the milestone.";
    writeFileSync(join(d3, "acceptance.json"), JSON.stringify(acc, null, 2), "utf8");
    const r3 = bunSrc(["pack", "build", d3]);
    expect(r3.status).toBe(1);
    expect(r3.stderr).toContain("50%");
  });

  it("refuses the three internal words (studio, foundry, workshop) and customer never-words", async () => {
    for (const internalWord of ["studio", "foundry", "workshop"]) {
      const dir = mk(`pack-word-${internalWord}`);
      await writeValidFixturePack(dir);
      writeFileSync(join(dir, "checklist.md"), `1. Ask the ${internalWord} team to check the slug.\n`, "utf8");
      const res = bunSrc(["pack", "build", dir]);
      expect(res.status).toBe(1);
      expect(res.stderr).toContain(`"${internalWord}"`);
    }

    for (const neverWord of ["template", "Passport", "GCC", "DID", "guardrails"]) {
      const dir = mk(`pack-never-${neverWord.toLowerCase()}`);
      await writeValidFixturePack(dir);
      const pj = JSON.parse(readFileSync(join(dir, "pack.json"), "utf8"));
      pj.summary = `A ready ${neverWord} for agencies.`;
      writeFileSync(join(dir, "pack.json"), JSON.stringify(pj, null, 2), "utf8");
      const res = bunSrc(["pack", "build", dir]);
      expect(res.status).toBe(1);
      expect(res.stderr).toMatch(/must not use/i);
    }
  });

  it("refuses a non-null or unlabelled node-descriptor slot (ADR-0029)", async () => {
    const dNonNull = mk("pack-desc-nonnull");
    await writeValidFixturePack(dNonNull);
    const pj1 = JSON.parse(readFileSync(join(dNonNull, "pack.json"), "utf8"));
    pj1.descriptor = { node: { version: 1 }, label: "Premature kernel descriptor" };
    writeFileSync(join(dNonNull, "pack.json"), JSON.stringify(pj1, null, 2), "utf8");
    const r1 = bunSrc(["pack", "build", dNonNull]);
    expect(r1.status).toBe(1);
    expect(r1.stderr).toContain("ADR-0029");

    const dEmptyLabel = mk("pack-desc-nolabel");
    await writeValidFixturePack(dEmptyLabel);
    const pj2 = JSON.parse(readFileSync(join(dEmptyLabel, "pack.json"), "utf8"));
    pj2.descriptor = { node: null, label: "   " };
    writeFileSync(join(dEmptyLabel, "pack.json"), JSON.stringify(pj2, null, 2), "utf8");
    const r2 = bunSrc(["pack", "build", dEmptyLabel]);
    expect(r2.status).toBe(1);
    expect(r2.stderr).toContain("descriptor.label");
  });

  it("refuses an open rule that breaks predicate's floor or drifts from rule.md", async () => {
    const dBadRule = mk("pack-bad-rule");
    await writeValidFixturePack(dBadRule);
    // An ascribed identity asked of a person (d85(b) rule 1, P4): predicate's vocabulary refuses "caste".
    const rule = JSON.parse(readFileSync(join(dBadRule, "rule.json"), "utf8"));
    rule.criteria[0].subject = "person";
    rule.criteria[0].answer.query[0].claims.push({ id: "caste", path: ["caste"] });
    writeFileSync(join(dBadRule, "rule.json"), JSON.stringify(rule, null, 2), "utf8");
    const r1 = bunSrc(["pack", "build", dBadRule]);
    expect(r1.status).toBe(1);
    expect(r1.stderr).toContain("Open rule failed floor validation");
    expect(r1.stderr).toContain("ASCRIBED_IDENTITY");

    const dDrift = mk("pack-hash-drift");
    await writeValidFixturePack(dDrift);
    writeFileSync(join(dDrift, "rule.md"), "# Drifted rule\n\n- **SHA-256 (JCS):** `0000`\n- **Licence:** CC BY 4.0\n", "utf8");
    const r2 = bunSrc(["pack", "build", dDrift]);
    expect(r2.status).toBe(1);
    expect(r2.stderr).toContain("must quote the open rule's SHA-256");
  });

  it("checks every pack against @kashscript/floor (RW-17): refuses undeclared routes, waivers, person-lookup, and declined-state", async () => {
    // 1. Undeclared screen/API route
    const dUndeclared = mk("pack-floor-undeclared");
    await writeValidFixturePack(dUndeclared);
    const fm1 = JSON.parse(readFileSync(join(dUndeclared, "floor.manifest.json"), "utf8"));
    delete fm1.routes["POST /api/v1/acceptances"];
    writeFileSync(join(dUndeclared, "floor.manifest.json"), JSON.stringify(fm1, null, 2), "utf8");
    const r1 = bunSrc(["pack", "build", dUndeclared]);
    expect(r1.status).toBe(1);
    expect(r1.stderr).toContain("undeclared-route");

    // 2. Floor person-lookup violation (d41, d85(b)2, d91(h)): a route that lists persons, even one the engine serves.
    const dLookup = mk("pack-floor-lookup");
    await writeValidFixturePack(dLookup);
    const fm2 = JSON.parse(readFileSync(join(dLookup, "floor.manifest.json"), "utf8"));
    fm2.routes["GET /api/v1/students"] = { subject: "person", shape: "list", outsideOracle: ENGINE_ROUTE };
    writeFileSync(join(dLookup, "floor.manifest.json"), JSON.stringify(fm2, null, 2), "utf8");
    const r2 = bunSrc(["pack", "build", dLookup]);
    expect(r2.status).toBe(1);
    expect(r2.stderr).toContain("[person-lookup]");
    expect(r2.stderr).toContain("d41");

    // 3. Floor declined-state violation (d49(a)): a decline returned for what a person answers.
    const dDeclined = mk("pack-floor-declined");
    await writeValidFixturePack(dDeclined);
    const fm3 = JSON.parse(readFileSync(join(dDeclined, "floor.manifest.json"), "utf8"));
    fm3.routes["GET /api/v1/approvals/:id"] = { subject: "record", shape: "one", states: ["declined"], outsideOracle: ENGINE_ROUTE };
    writeFileSync(join(dDeclined, "floor.manifest.json"), JSON.stringify(fm3, null, 2), "utf8");
    const r3 = bunSrc(["pack", "build", dDeclined]);
    expect(r3.status).toBe(1);
    expect(r3.stderr).toContain("[declined-state]");

    // 4b. A route a pack declares with no reason why its own oracle cannot see it: the floor reads it as stale.
    const dStale = mk("pack-floor-stale");
    await writeValidFixturePack(dStale);
    const fm5 = JSON.parse(readFileSync(join(dStale, "floor.manifest.json"), "utf8"));
    delete fm5.routes["POST /api/v1/acceptances"].outsideOracle;
    writeFileSync(join(dStale, "floor.manifest.json"), JSON.stringify(fm5, null, 2), "utf8");
    const r5 = bunSrc(["pack", "build", dStale]);
    expect(r5.status).toBe(1);
    expect(r5.stderr).toContain("[undeclared-route]");

    // 4. Waiver forbidden on set-up packs
    const dWaiver = mk("pack-floor-waiver");
    await writeValidFixturePack(dWaiver);
    const fm4 = JSON.parse(readFileSync(join(dWaiver, "floor.manifest.json"), "utf8"));
    fm4.waivers = [{ rule: "person-lookup", at: "GET /api/v1/x", reason: "never", expiresOn: "2027-01-01" }];
    writeFileSync(join(dWaiver, "floor.manifest.json"), JSON.stringify(fm4, null, 2), "utf8");
    const r4 = bunSrc(["pack", "build", dWaiver]);
    expect(r4.status).toBe(1);
    expect(r4.stderr).toMatch(/no floor waivers/i);
  });
});

describe("PY-8 set-up packs — one-command practice install and first approval", () => {
  const roots: string[] = [];
  const mk = (label: string): string => {
    const d = tempDir(label);
    roots.push(d);
    return d;
  };

  afterAll(() => {
    for (const d of roots) removeDir(d);
  });

  it("refuses to install on a server that is not running practice dev-echo mode (NOT_PRACTICE_HOST)", async () => {
    const packDir = mk("pack-prod-guard");
    await writeValidFixturePack(packDir);
    let orgCreated = false;
    const prodLike = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(req) {
        const url = new URL(req.url);
        if (url.pathname === "/api/v1/auth/request-link") {
          // Production hosts return 202 without `devToken`.
          return Response.json({ ok: true }, { status: 202 });
        }
        if (url.pathname === "/api/v1/orgs") orgCreated = true;
        return Response.json({ error: "not_found" }, { status: 404 });
      },
    });
    try {
      const res = bunSrc(["pack", "install", packDir, "--host", `http://127.0.0.1:${prodLike.port}`]);
      expect(res.status).toBe(1);
      expect(res.stderr).toContain("DUEDALE_AUTH_DEV_ECHO=1");
      expect(res.stderr).toContain("NOT_PRACTICE_HOST");
      expect(orgCreated).toBe(false);
    } finally {
      await prodLike.stop(true);
    }
  });

  it("refuses a host that echoes sign-in tokens but signs as production, before anything is configured", async () => {
    const packDir = mk("pack-prod-signing-guard");
    await writeValidFixturePack(packDir);
    const touched: string[] = [];
    const echoesButProduction = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      async fetch(req) {
        const url = new URL(req.url);
        touched.push(`${req.method} ${url.pathname}`);
        if (url.pathname === "/api/v1/auth/request-link") return Response.json({ ok: true, devToken: "t" }, { status: 202 });
        if (url.pathname === "/api/v1/auth/redeem") {
          return new Response("{}", { status: 200, headers: { "content-type": "application/json", "set-cookie": "oa_session=s; Path=/" } });
        }
        if (url.pathname === "/api/v1/orgs") {
          const body = (await req.json()) as { name: string; slug: string };
          return Response.json({ id: "org-1", name: body.name, slug: body.slug, issuer: { did: "did:kash:x" } }, { status: 201 });
        }
        if (url.pathname === "/api/v1/me") return Response.json({ org: { slug: "x", signing: { mode: "production" } } }, { status: 200 });
        return Response.json({ error: "not_found" }, { status: 404 });
      },
    });
    try {
      const res = bunSrc(["pack", "install", packDir, "--host", `http://127.0.0.1:${echoesButProduction.port}`]);
      expect(res.status).toBe(1);
      expect(res.stderr).toContain("NOT_PRACTICE_HOST");
      expect(res.stderr).toContain('signs as "production"');
      // Nothing after the organisation itself: no engagement, delivery or acceptance.
      expect(touched.filter((t) => t.includes("/engagements") || t.includes("/acceptances"))).toEqual([]);
    } finally {
      await echoesButProduction.stop(true);
    }
  });

  it("gives a practice organisation an address name Duedale accepts (3–30), for every pack slug", () => {
    for (const slug of ["client-sign-off", "internships-that-count", "host-receipts", "a-very-long-pack-slug-that-goes-on-and-on"]) {
      const name = practiceOrgSlug(slug);
      expect(name).toMatch(/^[a-z0-9][a-z0-9-]{2,29}$/);
      expect(name.startsWith("practice-")).toBe(true);
      expect(name).not.toMatch(/--/);
    }
    expect(practiceOrgSlug("internships-that-count", "a1b2")).toBe("practice-internships-that-a1b2");
  });

  it("installs a fixture pack on a clean local practice host in one command and verifies the first approval offline", async () => {
    const work = mk("pack-mock-install");
    const packDir = join(work, "fixture-pack");
    const outBundle = join(work, "approved.bundle.json");
    await writeValidFixturePack(packDir);

    // Minimal in-process practice host speaking the exact Duedale milestone sign-off wire shapes.
    const orgPair = await generateKeyPair();
    const orgDid = deriveDid(orgPair.publicKey);
    const orgSigningKey = {
      did: orgDid,
      publicKey: orgPair.publicKey,
      privateKey: orgPair.privateKey,
      custody: "subject-generated" as const,
    };
    let orgSlug = "";
    let orgAcceptance: SignedCountersignAcceptance | null = null;
    let storedBundle: CountersignBundle | null = null;
    let storedCountersigner = "";
    let recordEnvelope: DsseEnvelope | null = null;
    let answerForAnotherRecord = false;
    const receiptNo = ulid();
    const mockPort = await freeLoopbackPort();
    const mockOrigin = `http://127.0.0.1:${mockPort}`;

    const mockHost = Bun.serve({
      hostname: "127.0.0.1",
      port: mockPort,
      async fetch(req: Request): Promise<Response> {
        const url = new URL(req.url);
        if (req.method === "POST" && url.pathname === "/api/v1/auth/request-link") {
          return Response.json({ ok: true, devToken: "practice-token-1" }, { status: 202 });
        }
        if (req.method === "POST" && url.pathname === "/api/v1/auth/redeem") {
          return new Response(JSON.stringify({ ok: true }), {
            status: 200,
            headers: { "content-type": "application/json", "set-cookie": "oa_session=sess-1; Path=/; HttpOnly" },
          });
        }
        if (req.method === "POST" && url.pathname === "/api/v1/orgs") {
          // Duedale's answer (product-accounts.ts): the Org at the top level, with its signing key as `issuer.did`.
          const body = (await req.json()) as { name: string; slug: string };
          orgSlug = body.slug;
          return Response.json({ id: "org-1", name: body.name, slug: body.slug, issuer: { did: orgDid } }, { status: 201 });
        }
        if (req.method === "GET" && url.pathname === "/api/v1/me") {
          return Response.json({ org: { slug: orgSlug, issuer: { did: orgDid }, signing: { mode: "practice" } } }, { status: 200 });
        }
        if (req.method === "POST" && url.pathname === "/api/v1/engagements") {
          return Response.json({ id: "eng-1", milestones: [{ id: "ms-1" }] }, { status: 201 });
        }
        if (req.method === "POST" && url.pathname === "/api/v1/engagements/eng-1/milestones/ms-1/deliver") {
          const nowSec = Math.floor(Date.now() / 1000);
          const payloadObj = {
            spec: "oreoasis.work-record/1",
            receiptId: receiptNo,
            org: orgSlug,
            actor: { class: "org", id: orgDid },
            shape: "accepted",
            action: { type: "milestone.delivered", summary: "Milestone 1 — Practice hand-off" },
            inputs: [],
            outputs: [],
            status: "completed",
            timestamp: new Date(nowSec * 1000).toISOString(),
            meta: { profile: "oreoasis-milestone/2" },
          };
          const payloadBytes = canonicalizeBytes(payloadObj);
          const payloadType = "application/vnd.oreoasis.work-record+json";
          const subject: DsseEnvelope = {
            payloadType,
            payload: bytesToBase64(payloadBytes),
            signatures: [],
          };
          const created = await createCountersignRequest({
            subject,
            requesterDid: orgDid,
            requesterPrivateKey: orgPair.privateKey,
            statement: SAMPLE_STATEMENT,
            disclosures: [{ label: "Milestone", value: "Milestone 1 — Practice hand-off" }],
            relationshipContext: "engagement-milestone",
            ttlSeconds: 14 * 86_400,
          });
          const byOrg = await acceptCountersignRequest({
            request: created.request,
            subject,
            signingKey: orgSigningKey,
          });
          if (!byOrg.ok) {
            return Response.json({ error: byOrg.reason }, { status: 500 });
          }
          orgAcceptance = byOrg.acceptance;
          recordEnvelope = byOrg.envelope;
          const frag = bytesToBase64Url(new TextEncoder().encode(JSON.stringify({ r: created.compactB64u, e: byOrg.envelope })));
          return Response.json(
            { receiptNo, link: `${mockOrigin}/approve/#v1.${frag}` },
            { status: 201 },
          );
        }
        if (req.method === "POST" && url.pathname === "/api/v1/acceptances") {
          const body = (await req.json()) as {
            request: SignedCountersignRequest;
            acceptance: SignedCountersignAcceptance;
            envelope: DsseEnvelope;
          };
          storedBundle = assembleCountersignBundle({
            subject: body.envelope,
            request: body.request,
            acceptances: [orgAcceptance!, body.acceptance],
          });
          storedCountersigner = body.acceptance.body.countersignerDid;
          return Response.json({ ok: true }, { status: 201 });
        }
        if (req.method === "GET" && url.pathname === `/api/v1/verify/${receiptNo}/bundle`) {
          // Duedale's public verify answer (receipts.ts): the record's envelope, and each acceptance with its kernel bundle.
          return Response.json(
            {
              receiptNo,
              envelope: answerForAnotherRecord
                ? { ...recordEnvelope!, payload: bytesToBase64(new TextEncoder().encode('{"another":"record"}')) }
                : recordEnvelope,
              acceptances: [{ countersignerDid: storedCountersigner, grade: "0", bundle: storedBundle }],
            },
            { status: 200 },
          );
        }
        return Response.json({ error: "not_found" }, { status: 404 });
      },
    });

    try {
      const installed = bunSrc([
        "pack",
        "install",
        packDir,
        "--host",
        mockOrigin,
        "--out",
        outBundle,
        "--json",
      ]);
      expect(installed.status).toBe(0);
      const result = JSON.parse(installed.stdout);
      expect(result.packSlug).toBe("fixture-sign-off");
      expect(result.approval.verifiedOffline).toBe(true);
      expect(existsSync(outBundle)).toBe(true);

      // Verify offline via bundled plain-Node CLI under offline-guard.cjs!
      const verified = nodeDist(["verify", outBundle]);
      expect(verified.status).toBe(0);
      expect(verified.stdout).toContain("RESULT: PASS");

      // A verify answer whose acceptance is about another record is refused, though the bundle itself verifies.
      answerForAnotherRecord = true;
      const lied = bunSrc(["pack", "install", packDir, "--host", mockOrigin]);
      expect(lied.status).toBe(1);
      expect(lied.stderr).toContain("VERIFY_FAILED");
      expect(lied.stderr).toContain("not about the milestone");
    } finally {
      await mockHost.stop(true);
    }
  });
});

if (HAS_ARCHIVE_PACKS && HAS_DUEDALE_HOST) {
  describe("PY-8 set-up packs — real end-to-end practice install on Duedale 2.0", () => {
    let serverProc: ChildProcess | null = null;
    let hostOrigin = "";
    const outDir = tempDir("duedale-pack-e2e");

    beforeAll(async () => {
      const port = await freeLoopbackPort();
      hostOrigin = `http://127.0.0.1:${port}`;
      serverProc = spawn(
        process.execPath,
        ["run", "scripts/e2e-server.ts"],
        {
          cwd: DUEDALE_HOST_DIR,
          env: {
            ...process.env,
            DUEDALE_PORT: String(port),
            DUEDALE_AUTH_DEV_ECHO: "1",
            DUEDALE_E2E_PRACTICE_WITNESS: "0",
            DUEDALE_PUBLIC_APP_BASE: hostOrigin,
            DUEDALE_JWT_SECRET: "practice-jwt-secret-py8-simulation-only-000000",
            DUEDALE_SESSION_SECRET: "practice-session-secret-py8-simulation-only-00",
            DUEDALE_KEY_ENCRYPTION_SECRET: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          },
          stdio: ["ignore", "pipe", "pipe"],
          windowsHide: true,
        },
      );

      let bootErr = "";
      serverProc.stderr?.on("data", (chunk: Buffer) => {
        bootErr += chunk.toString("utf8");
      });

      const deadline = Date.now() + 20_000;
      let ready = false;
      while (Date.now() < deadline) {
        if (serverProc.exitCode !== null) {
          throw new Error(`Duedale e2e-server exited early (${serverProc.exitCode}):\n${bootErr}`);
        }
        try {
          const res = await fetch(`${hostOrigin}/healthz`);
          if (res.ok) {
            ready = true;
            break;
          }
        } catch {
          /* wait for listen */
        }
        await new Promise((r) => setTimeout(r, 150));
      }
      if (!ready) {
        throw new Error(`Timed out waiting for Duedale practice server at ${hostOrigin}/healthz:\n${bootErr}`);
      }
    });

    afterAll(() => {
      if (serverProc && serverProc.exitCode === null) {
        serverProc.kill();
      }
      removeDir(outDir);
    });

    for (const slug of ["client-sign-off", "internships-that-count", "host-receipts"] as const) {
      it(`installs packs/${slug} on a clean Duedale practice organisation with one command and verifies its first approval offline`, () => {
        const packDir = join(PACKS_ROOT, slug);
        const outFile = join(outDir, `${slug}.approved.json`);
        const installed = bunSrc([
          "pack",
          "install",
          packDir,
          "--host",
          hostOrigin,
          "--out",
          outFile,
          "--json",
        ]);
        if (installed.status !== 0) {
          throw new Error(`kash pack install ${slug} failed (${installed.status}):\n${installed.stdout}\n${installed.stderr}`);
        }
        const report = JSON.parse(installed.stdout) as {
          packSlug: string;
          flow: string;
          org: { name: string; slug: string; did: string };
          approval: {
            artifactKind: string;
            receiptRef: string;
            countersignerDid: string;
            verifiedOffline: boolean;
          };
        };
        expect(report.packSlug).toBe(slug);
        expect(report.flow).toBe(slug);
        expect(report.org.name).toMatch(/practice/i);
        expect(report.org.did).toStartWith("did:kash:");
        expect(report.approval.countersignerDid).toStartWith("did:kash:");
        expect(report.approval.verifiedOffline).toBe(true);
        expect(existsSync(outFile)).toBe(true);

        // Check offline with `kash verify` under plain Node + offline-guard.cjs.
        const verified = nodeDist(["verify", outFile]);
        expect(verified.status).toBe(0);
        expect(verified.stdout).toContain("RESULT: PASS");
      });
    }
  });
}
