#!/usr/bin/env bun
/**
 * Writes the decision example of the attestation profile — a `kash.decision@1.2.0` a credit officer's seat
 * signed under the lender's mandate — into `specs/attestation/examples/decision-person-mandate/` (RW-14).
 *
 * **Run once; never regenerated.** Keys are made fresh and thrown away; only public identifiers and signed
 * bytes are written. Salts are random, so the test checks what was written and never re-runs this. The rule is
 * the income fixture, SAMPLE figures, `practice: true`.
 *
 *   bun scripts/decision-example.ts
 */

import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { deriveDid, generateKeyPair, type KashKeyPair } from "@kashscript/identity-core";
import { signEnvelope } from "@kashscript/attest/dsse";
import { checkMandate, MANDATE_DST, payloadSha256, type MandateBody } from "@kashscript/attest/attestation";
import { decidePerson, issueDecision, readDecision, validateDecision } from "../src/decision";
import { readRule, signRule } from "../src/rule";
import { incomeRule, PRACTICE_AS_OF } from "../src/fixtures";

const OUT = join(import.meta.dir, "..", "..", "..", "specs", "attestation", "examples", "decision-person-mandate");
const DAY = 86_400;
const json = (v: unknown): string => `${JSON.stringify(v, null, 2)}\n`;

type Party = KashKeyPair & { readonly did: string; readonly keyid: string };
async function party(): Promise<Party> {
  const kp = await generateKeyPair();
  const did = deriveDid(kp.publicKey);
  return { ...kp, did, keyid: did };
}

async function main(): Promise<void> {
  if (existsSync(OUT)) throw new Error(`${OUT} exists — the examples are generated once and never regenerated`);
  const [lender, officer, payrollIssuer, personAtDesk] = await Promise.all([party(), party(), party(), party()]);

  const ruleEnvelope = await signRule(incomeRule({ lender: lender.did, predicateIssuer: payrollIssuer.did }), lender);
  const rule = await readRule(ruleEnvelope);

  // The lender grants one seat — a credit officer's sign-in — the authority to decide under its rules (d91(a)).
  const mandate: MandateBody = {
    id: `${lender.did}/mandate/credit-officer-seat`,
    principal: lender.did,
    delegate: { key: officer.did, kind: "seat", role: "Credit officer" },
    scope: { kinds: ["decision"], outcomes: ["accepted", "not-yet", "refused"] },
    dates: { from: "2026-10-01T00:00:00Z", until: "2027-09-30T00:00:00Z" },
    credentialStatus: { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: "33418", statusListCredential: "https://lender.example/status/mandates" },
    practice: true,
  };
  const checked = checkMandate(mandate);
  if (!checked.ok) throw new Error(`the mandate does not check: ${checked.faults.map((f) => f.code).join(", ")}`);
  const mandateEnvelope = await signEnvelope(mandate, MANDATE_DST, lender, { canonical: true });
  const mandateSha = await payloadSha256(mandateEnvelope);

  // The rule binds (a loan offer), so a named person decides (d84 P3); their seat cites its mandate (1.2.0).
  const body = await decidePerson({
    rule,
    outcome: "yes",
    reasons: ["income-shown"],
    fired: rule.body.criteria.map((c) => c.id),
    missing: [],
    reliedOn: ["5d41402abc4b2a76b9719d911017c592ae2f1e3c5b7d9f1a3c5e7092b4d6f8a1"],
    seat: { role: "Credit officer", did: officer.did, signer: officer, mandate: { id: mandate.id, hash: mandateSha } },
    decidedAt: PRACTICE_AS_OF,
  });
  // Checked whole: the mandate presented beside the decision (1.2.0).
  const v = await validateDecision(body, rule, undefined, { mandate: mandateEnvelope });
  if (!v.ok || v.notChecked !== undefined) throw new Error(`the decision does not validate: ${v.refusals.map((r) => r.code).join(", ")}`);

  const iat = Date.parse(PRACTICE_AS_OF) / 1000;
  const copy = await issueDecision({ body, rule, issuer: { ...lender, did: lender.did }, holderPublicKey: personAtDesk.publicKey, iatUnix: iat, expUnix: iat + 365 * DAY });
  const read = await readDecision(copy, { nowSec: iat + 60 });
  if (read === null || !read.ok) throw new Error("the copy does not read");

  mkdirSync(OUT, { recursive: true });
  writeFileSync(join(OUT, "rule.dsse.json"), json(ruleEnvelope));
  writeFileSync(join(OUT, "mandate.body.json"), json(mandate));
  writeFileSync(join(OUT, "mandate.dsse.json"), json(mandateEnvelope));
  writeFileSync(join(OUT, "decision.body.json"), json(body));
  writeFileSync(join(OUT, "copy.sd-jwt.txt"), `${copy}\n`);
  writeFileSync(
    join(OUT, "context.json"),
    json({
      note: "SAMPLE parties, practice only. Public identifiers; no key material.",
      lender: lender.did,
      seat: officer.did,
      copyKey: personAtDesk.did,
      rule: { id: rule.body.id, version: rule.body.version, hash: rule.hash },
      mandate: { id: mandate.id, hash: mandateSha },
      checkAt: iat + 60,
    }),
  );
  console.log(`wrote ${OUT}`);
}

await main();
