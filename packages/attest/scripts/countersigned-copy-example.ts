#!/usr/bin/env bun
/**
 * Writes the worked example of a copy of a countersigned record — the records already in use, given RW-14's
 * copy (RW-15; `specs/attestation/README.md` §2.4a–§2.4b) — into
 * `specs/attestation/examples/receipt-booking-countersigned/`.
 *
 * **Run once; never regenerated.** The keys are made fresh here and thrown away: only public keys, DIDs and
 * signed bytes are written, so the example carries no key material. SD-JWT salts and the seal's IV are random,
 * so a second run would write different bytes — the test checks what was written, never re-runs this. Every
 * party is SAMPLE and the record is `practice: true`.
 *
 *   bun scripts/countersigned-copy-example.ts            # refuses to overwrite the example
 *
 * What it writes: the record of truth as the engines sign it today (`record.countersign.json`: the host's
 * `booking.delivered/1` work record, asked for by the host, countersigned by the guest); two copies to two
 * verifiers and their presentations, disclosing nothing; the VC 2.0 projection of what the first verifier saw;
 * and a page — the stored copy with no key, the fragment the viewer holds, the artefact sealed under the
 * `record` disclosure.
 */

import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { makeKeyResolver } from "../src/holder";
import { issueSdJwt, presentSdJwt, verifySdJwt } from "../src/sd-jwt";
import { copyClaimsOfCountersigned, openPage, pageOf, projectVc, readCountersigned, viewOfCopy } from "../src/attestation";
import type { VerifyKey } from "../src/signing";
import { bookingDelivered, party, type Party } from "../test/helpers/countersigned";

const OUT = join(import.meta.dir, "..", "..", "..", "specs", "attestation", "examples", "receipt-booking-countersigned");

/** The example's clock: a stay in mid-November, the copies issued on 2026-11-23 and shown that day. */
const STAY_START = Date.parse("2026-11-14T12:00:00Z") / 1000;
const STAY_END = Date.parse("2026-11-16T10:00:00Z") / 1000;
const ISSUED = Date.parse("2026-11-23T00:00:00Z") / 1000;
const PRESENTED_A = Date.parse("2026-11-23T09:30:00Z") / 1000;
const PRESENTED_B = Date.parse("2026-11-23T14:12:00Z") / 1000;
const VERIFIER_A = "https://review-door.example/verifier";
const VERIFIER_B = "https://loyalty-desk.example/verifier";
const NONCE_A = "sample-nonce-review-door";
const NONCE_B = "sample-nonce-loyalty-desk";
const NOTE = "SAMPLE parties, practice only. Public identifiers; no key material.";

const json = (v: unknown): string => `${JSON.stringify(v, null, 2)}\n`;
const resolver = makeKeyResolver(new Map(), new Map());

async function main(): Promise<void> {
  if (existsSync(OUT)) throw new Error(`${OUT} exists — the example is generated once and never regenerated`);
  const [host, guest, keyA, keyB] = await Promise.all([party(), party(), party(), party()]);

  // The record of truth, as the engine signs it today (Duedale since d99): the host's work record, the host's request, the guest's acceptance.
  const record = await bookingDelivered(host, guest, { start: STAY_START, end: STAY_END, practice: true });
  const reading = await readCountersigned(record);
  if (!reading.report.ok || !reading.report.twoSignatureProof || reading.record === null) throw new Error(`the record does not check: ${reading.report.reason}`);

  // One copy per verifier, and one for a page: the same class, fresh salts, a key only where a verifier will see it.
  const copyOf = async (holderKey?: VerifyKey): Promise<string> => {
    const { claims, sdProperties, decoys } = await copyClaimsOfCountersigned(record, { issuer: host.did, ...(holderKey !== undefined ? { holderKey } : {}), iatUnix: ISSUED, grade: 1 });
    return issueSdJwt({ header: { kid: host.did }, claims, sdProperties, decoys, signer: host });
  };
  const copyA = await copyOf(keyA.publicKey);
  const copyB = await copyOf(keyB.publicKey);
  const pageCopy = await copyOf();

  const present = async (held: string, holder: Party, aud: string, nonce: string, iatUnix: number): Promise<string> => {
    const p = await presentSdJwt(held, () => false, holder, { aud, nonce, iatUnix });
    const seen = await verifySdJwt(p, { resolveKey: resolver, requireKeyBinding: true, audience: aud, nonce, nowSec: iatUnix + 60 });
    if (!seen.ok || seen.claims === null) throw new Error(`the presentation to ${aud} does not verify (${seen.reason})`);
    return p;
  };
  const presentationA = await present(copyA, keyA, VERIFIER_A, NONCE_A, PRESENTED_A);
  const presentationB = await present(copyB, keyB, VERIFIER_B, NONCE_B, PRESENTED_B);
  const seenByA = await verifySdJwt(presentationA, { resolveKey: resolver, requireKeyBinding: true, audience: VERIFIER_A, nonce: NONCE_A, nowSec: PRESENTED_A + 60 });

  // The page: the host stores the copy's commitments and the sealed artefact; the viewer's link carries the fragment.
  const page = await pageOf(pageCopy, record);
  const opened = await openPage(page, { nowSec: PRESENTED_A + 60 });
  if (opened.shown === null) throw new Error(`the page does not open for its viewer: ${opened.why}`);
  const closed = await openPage({ ...page, fragment: "" }, { nowSec: PRESENTED_A + 60 });
  if (closed.shown !== null) throw new Error("the page shows the artefact without the disclosure");

  mkdirSync(join(OUT, "page"), { recursive: true });
  const files: Record<string, string> = {
    "record.countersign.json": json(record),
    "copy-a.sd-jwt.txt": `${copyA}\n`,
    "presentation-a.sd-jwt.txt": `${presentationA}\n`,
    "copy-b.sd-jwt.txt": `${copyB}\n`,
    "presentation-b.sd-jwt.txt": `${presentationB}\n`,
    "projection.vc.json": json(projectVc(viewOfCopy(seenByA.claims!))),
    "page/copy.sd-jwt.txt": `${page.copy}\n`,
    "page/fragment.txt": `${page.fragment}\n`,
    "page/artefact.jwe.txt": `${page.artefact}\n`,
    "context.json": json({
      note: NOTE,
      issuer: host.did,
      counterparty: guest.did,
      record: reading.record,
      profile: "booking.delivered/1",
      grade: 1,
      presentations: {
        a: { audience: VERIFIER_A, nonce: NONCE_A, iatUnix: PRESENTED_A, disclosed: [], copyKey: keyA.did },
        b: { audience: VERIFIER_B, nonce: NONCE_B, iatUnix: PRESENTED_B, disclosed: [], copyKey: keyB.did },
      },
      page: { disclosed: ["record", "statement", "claimedAt"], holderKey: "none — a page copy cannot be presented" },
      checkAt: PRESENTED_B + 60,
    }),
  };
  for (const [name, text] of Object.entries(files)) writeFileSync(join(OUT, name), text);
  console.log(`wrote ${Object.keys(files).length} files to ${OUT}`);
}

await main();
