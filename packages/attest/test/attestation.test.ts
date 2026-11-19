/**
 * RW-14 — the attestation profile (`specs/attestation/README.md` §2). Every worked example under
 * `specs/attestation/examples/` is checked in each of its forms against what the spec says it is, and every
 * conformance case under `specs/attestation/tck/` reaches its stated result. The examples were generated once
 * (`scripts/attestation-examples.ts`) and are never regenerated: this reads them, it never re-runs the script.
 */

import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalizeBytes, deriveDid, generateKeyPair } from "@kashscript/identity-core";
import { getSchemaDefinition } from "@kashscript/lexicons/engine";
import { LexiconRegistry } from "@kashscript/lexicons/registry";
import { validate } from "@kashscript/lexicons/schema";
import { base64ToBytes, bytesToBase64 } from "../src/ed25519";
import { pae, signEnvelope, verifyEnvelope, type DsseEnvelope } from "../src/dsse";
import { lookupDst } from "../src/dst";
import { resolveDidKey, signBytes } from "../src/signing";
import { makeKeyResolver } from "../src/holder";
import { decodeDisclosure, decodeJws, issueSdJwt, keyOfJwk, linkabilityBetween, parseSdJwt, presentSdJwt, verifySdJwt } from "../src/sd-jwt";
import {
  ATTESTATION_DST,
  ATTESTATION_VC_SCHEMA,
  ATTESTATION_VCT,
  COPY_LIFETIME_DAYS,
  COPY_SD_SLOTS,
  KASH_ATTESTATION_ID,
  KASH_ATTESTATION_LEXICON,
  KASH_MANDATE_ID,
  KASH_MANDATE_LEXICON,
  MANDATE_DST,
  attestationVcJsonSchema,
  checkAttestation,
  checkMandate,
  copyClaimsOf,
  isPublicReference,
  payloadSha256,
  principalOfMandateId,
  projectVc,
  verifyAttestationRecord,
  viewOfCopy,
  type AttestationBody,
  type MandateBody,
  type RecordCheckOptions,
} from "../src/attestation";

const SPECS = join(import.meta.dir, "..", "..", "..", "specs");
const EXAMPLES = join(SPECS, "attestation", "examples");
const TCK = join(SPECS, "attestation", "tck");
const DAY = 86_400;
const read = (...p: string[]): string => readFileSync(join(...p), "utf8");
const readJson = <T = unknown>(...p: string[]): T => JSON.parse(read(...p)) as T;
const resolver = makeKeyResolver(new Map(), new Map());

interface Context {
  readonly issuer: string;
  readonly signers: { readonly issuer: string; readonly counterparty?: string };
  readonly record: string;
  readonly presentation?: { readonly audience: string; readonly nonce: string; readonly iatUnix: number; readonly disclosed: readonly string[] };
  readonly checkAt?: number;
}

const env = (...p: string[]): DsseEnvelope => readJson<DsseEnvelope>(EXAMPLES, ...p);
/** What each example's record needs presented beside it. */
const OPTIONS: Readonly<Record<string, RecordCheckOptions>> = {
  "receipt-client-signoff": { counterpartyMandate: env("receipt-client-signoff", "counterparty-mandate.dsse.json") },
  "receipt-not-yet": { counterpartyMandate: env("receipt-client-signoff", "counterparty-mandate.dsse.json") },
  "receipt-booking": {},
  supersession: { superseded: env("receipt-booking", "record.dsse.json") },
  "finding-under-mandate": { mandate: env("mandate-seat", "record.dsse.json") },
};
const RECORDS = Object.keys(OPTIONS);
const THREE_FORMS = ["finding-under-mandate", "receipt-booking", "supersession"];

describe("the worked examples are what the spec says", () => {
  test("five records; three are shown in all three forms, two stay with their parties", () => {
    const dirs = readdirSync(EXAMPLES).sort();
    expect(dirs).toEqual(["decision-person-mandate", "finding-under-mandate", "mandate-seat", "receipt-booking", "receipt-client-signoff", "receipt-not-yet", "supersession"]);
    for (const d of THREE_FORMS) expect(readdirSync(join(EXAMPLES, d))).toEqual(expect.arrayContaining(["copy.sd-jwt.txt", "presentation.sd-jwt.txt", "projection.vc.json"]));
    for (const d of ["receipt-client-signoff", "receipt-not-yet"]) expect(readdirSync(join(EXAMPLES, d))).not.toContain("copy.sd-jwt.txt");
  });

  for (const name of RECORDS) {
    describe(`${name} — the record of truth`, () => {
      const body = readJson<AttestationBody>(EXAMPLES, name, "body.json");
      const record = env(name, "record.dsse.json");
      const context = readJson<Context>(EXAMPLES, name, "context.json");
      const opts = OPTIONS[name]!;

      test("the body validates and is the canonical payload under the registered tag", () => {
        expect(checkAttestation(body)).toEqual({ ok: true, body, faults: [] });
        expect(record.payloadType).toBe(ATTESTATION_DST);
        expect(Buffer.from(base64ToBytes(record.payload)).equals(Buffer.from(canonicalizeBytes(body)))).toBe(true);
      });

      test("the stranger's check passes, and names what it could not decide", async () => {
        const r = await verifyAttestationRecord(record, opts);
        expect(r.problems).toEqual([]);
        expect(r.ok).toBe(true);
        expect(r.contentId).toBe(context.record);
        expect(r.notChecked.join(" ")).toContain("witnessed time");
        expect(r.notChecked.join(" ")).toContain("independent");
      });

      test("the signers are exactly the issuer's side and the counterparty's side, each checking with no lookup", async () => {
        const v = await verifyEnvelope(record, resolveDidKey);
        expect(v.verifiedKeyids.length).toBe(record.signatures.length);
        expect([...v.verifiedKeyids].sort()).toEqual([context.signers.issuer, ...(context.signers.counterparty !== undefined ? [context.signers.counterparty] : [])].sort());
      });

      test("without the other side's signature it is a request, not a record — and gets no copy", async () => {
        const counterpartySigner = context.signers.counterparty!;
        const one = { ...record, signatures: record.signatures.filter((s) => s.keyid !== counterpartySigner) };
        const r = await verifyAttestationRecord(one, opts);
        expect(r.ok).toBe(false);
        expect(r.problems.map((p) => p.code)).toEqual([body.counterpartyMandate !== undefined ? "MANDATE_INVALID" : "COUNTERPARTY_SIGNATURE"]);
        const k = await generateKeyPair();
        await expect(copyClaimsOf(one, { holderKey: k.publicKey, iatUnix: 1_795_046_400 }, opts)).rejects.toThrow("a copy is made only from a record of truth that checks");
      });

      if (body.mandate !== undefined || body.counterpartyMandate !== undefined) {
        test("a cited mandate that is not presented is a problem, never a pass", async () => {
          const r = await verifyAttestationRecord(record, {});
          expect(r.ok).toBe(false);
          expect(new Set(r.problems.map((p) => p.code))).toEqual(new Set(["MANDATE_MISSING"]));
        });
      }
    });
  }

  for (const name of THREE_FORMS) {
    describe(`${name} — the copy, the presentation, the projection`, () => {
      const body = readJson<AttestationBody>(EXAMPLES, name, "body.json");
      const record = env(name, "record.dsse.json");
      const context = readJson<Context>(EXAMPLES, name, "context.json");
      const opts = OPTIONS[name]!;
      const copy = read(EXAMPLES, name, "copy.sd-jwt.txt").trim();
      const presentation = read(EXAMPLES, name, "presentation.sd-jwt.txt").trim();
      const projection = readJson<Record<string, unknown>>(EXAMPLES, name, "projection.vc.json");
      const p = context.presentation!;

      test("the copy: issued by the issuer's own key, its claims exactly copyClaimsOf(record)", async () => {
        const held = await verifySdJwt(copy, { resolveKey: resolver, requireKeyBinding: false, nowSec: context.checkAt! });
        expect(held.ok).toBe(true);
        expect(held.vct).toBe(ATTESTATION_VCT);
        expect(held.issuer).toBe(body.issuer);
        const c = held.claims!;
        const key = keyOfJwk((c.cnf as { jwk: unknown }).jwk)!;
        const want = await copyClaimsOf(record, { holderKey: key, iatUnix: c.iat as number, ...(c.credentialStatus !== undefined ? { credentialStatus: c.credentialStatus as never } : {}) }, opts);
        const { _sd, _sd_alg, ...got } = c;
        void _sd;
        void _sd_alg;
        expect(got).toEqual(JSON.parse(JSON.stringify({ ...want.claims, ...want.sdProperties })));
      });

      test("its dates are its own — issued on a whole day, ending its lifetime later — and its _sd is padded to the fixed count", () => {
        const visible = decodeJws(parseSdJwt(copy)!.issuerJwt)!.payload;
        const iat = visible.iat as number;
        expect(iat % DAY).toBe(0);
        expect(visible.exp).toBe(iat + COPY_LIFETIME_DAYS * DAY);
        expect((visible._sd as string[]).length).toBe(COPY_SD_SLOTS);
        expect(visible.credentialStatus).toBeUndefined();
      });

      test("what could join two copies is never visible; the counterparty is nowhere in it", async () => {
        const parsed = parseSdJwt(copy)!;
        const visible = decodeJws(parsed.issuerJwt)!.payload;
        for (const k of ["statement", "claimedAt", "record", "mandate", "supersedes", "contests", "reasons", "counterparty", "counterpartyMandate"]) expect(visible[k]).toBeUndefined();
        if (isPublicReference(body.reference.kind)) expect(visible.reference).toEqual(body.reference);
        else expect(visible.reference).toBeUndefined();
        const disclosed = await Promise.all(parsed.disclosures.map(decodeDisclosure));
        expect(disclosed.some((d) => d?.name === "counterparty" || d?.name === "counterpartyMandate")).toBe(false);
        expect(JSON.stringify(visible)).not.toContain(body.counterparty!);
        expect(JSON.stringify(disclosed)).not.toContain(body.counterparty!);
      });

      test("the presentation binds this verifier's audience and nonce and discloses only what the holder chose", async () => {
        const r = await verifySdJwt(presentation, { resolveKey: resolver, requireKeyBinding: true, audience: p.audience, nonce: p.nonce, nowSec: context.checkAt! });
        expect(r.ok).toBe(true);
        expect(r.disclosed.map((d) => String(d.path[0])).sort()).toEqual([...p.disclosed].sort());
        const wrong = await verifySdJwt(presentation, { resolveKey: resolver, requireKeyBinding: true, audience: "https://someone-else.example", nonce: p.nonce, nowSec: context.checkAt! });
        expect(wrong.ok).toBe(false);
      });

      test("the projection is projectVc of what the verifier saw, fits its schema, and never names the counterparty", async () => {
        const r = await verifySdJwt(presentation, { resolveKey: resolver, requireKeyBinding: true, audience: p.audience, nonce: p.nonce, nowSec: context.checkAt! });
        expect(projection).toEqual(JSON.parse(JSON.stringify(projectVc(viewOfCopy(r.claims!)))));
        expect(validate(ATTESTATION_VC_SCHEMA, projection).ok).toBe(true);
        expect(projection.credentialSubject as Record<string, unknown>).not.toHaveProperty("id");
        expect(JSON.stringify(projection)).not.toContain(body.counterparty!);
      });
    });
  }

  test("the mandates validate, carry a status entry, and are signed by their principals alone", async () => {
    for (const [dir, file] of [["mandate-seat", "record.dsse.json"], ["receipt-client-signoff", "counterparty-mandate.dsse.json"]] as const) {
      const m = env(dir, file);
      const body = JSON.parse(new TextDecoder().decode(base64ToBytes(m.payload))) as MandateBody;
      expect(m.payloadType).toBe(MANDATE_DST);
      expect(checkMandate(body).ok).toBe(true);
      expect(body.credentialStatus.type).toBe("BitstringStatusListEntry");
      expect(Buffer.from(base64ToBytes(m.payload)).equals(Buffer.from(canonicalizeBytes(body)))).toBe(true);
      expect((await verifyEnvelope(m, resolveDidKey)).verifiedKeyids).toEqual([body.principal]);
    }
  });

  test("a mandate presented for the wrong side, or the wrong record, does not pass", async () => {
    const finding = env("finding-under-mandate", "record.dsse.json");
    const r = await verifyAttestationRecord(finding, { mandate: env("receipt-client-signoff", "counterparty-mandate.dsse.json") });
    expect(r.ok).toBe(false);
    expect(new Set(r.problems.map((x) => x.code))).toEqual(new Set(["MANDATE_INVALID"]));
  });

  test("the supersession example cites the first booking by its content id, with the same issuer, kind and counterparty", async () => {
    const corrected = readJson<AttestationBody>(EXAMPLES, "supersession", "body.json");
    expect(corrected.supersedes).toBe(await payloadSha256(env("receipt-booking", "record.dsse.json")));
    const unchecked = await verifyAttestationRecord(env("supersession", "record.dsse.json"));
    expect(unchecked.ok).toBe(true);
    expect(unchecked.notChecked.join(" ")).toContain("the superseded record was not presented");
  });

  test("no example carries key material", () => {
    for (const dir of readdirSync(EXAMPLES)) {
      for (const f of readdirSync(join(EXAMPLES, dir))) expect(read(EXAMPLES, dir, f)).not.toMatch(/privateKey|secretKey|"seed"|"d":|BEGIN [A-Z ]*PRIVATE KEY/);
    }
  });
});

/* ── records made here, with fresh keys, for the failure paths and the copies' privacy ── */

type Party = Awaited<ReturnType<typeof generateKeyPair>> & { readonly did: string; readonly keyid: string };
async function party(): Promise<Party> {
  const k = await generateKeyPair();
  const did = deriveDid(k.publicKey);
  return { ...k, did, keyid: did };
}
async function twoSigned(body: AttestationBody, issuer: Party, counterparty: Party, canonical = true): Promise<DsseEnvelope> {
  const e = await signEnvelope(body, ATTESTATION_DST, counterparty, { canonical });
  const sig = await signBytes(issuer, pae(e.payloadType, base64ToBytes(e.payload)), "der");
  return { ...e, signatures: [...e.signatures, { keyid: issuer.keyid, sig: bytesToBase64(sig) }] };
}
const booking = (issuer: string, counterparty: string, over: Partial<AttestationBody> = {}): AttestationBody => ({
  issuer,
  kind: "receipt",
  outcome: "accepted",
  reference: { kind: "agreement", sha256: "a7c3e9f1b5d7a3c9e1f5b7d3a9c5e1f7b3d9a5c1e7f3b9d5a1c7e3f9b5d1a7c3", version: 1 },
  statement: "Two nights, delivered as booked.",
  profile: "booking.delivered/1",
  counterparty,
  grade: 1,
  claimedAt: "2026-11-16T11:00:00Z",
  expiresAt: "2028-11-16T11:00:00Z",
  practice: true,
  ...over,
});

describe("the stranger's check refuses what it cannot bind", () => {
  test("another payloadType, a changed payload, a payload that is not canonical", async () => {
    const [host, guest] = await Promise.all([party(), party()]);
    const record = await twoSigned(booking(host.did, guest.did), host, guest);
    expect((await verifyAttestationRecord({ ...record, payloadType: "application/vnd.oreoasis.work-record+json" })).problems.map((p) => p.code)).toEqual(["WRONG_TYPE"]);
    const changed = { ...record, payload: bytesToBase64(canonicalizeBytes(booking(host.did, guest.did, { statement: "Three nights." }))) };
    expect(new Set((await verifyAttestationRecord(changed)).problems.map((p) => p.code))).toEqual(new Set(["ISSUER_SIGNATURE", "COUNTERPARTY_SIGNATURE"]));
    const loose = await twoSigned(booking(host.did, guest.did), host, guest, false);
    expect((await verifyAttestationRecord(loose)).problems.map((p) => p.code)).toEqual(["NOT_CANONICAL"]);
  });
  test("only the same issuer, kind and counterparty supersede a record", async () => {
    const [host, guest, stranger] = await Promise.all([party(), party(), party()]);
    const first = await twoSigned(booking(host.did, guest.did), host, guest);
    const sha = await payloadSha256(first);
    const fair = await twoSigned(booking(host.did, guest.did, { supersedes: sha }), host, guest);
    expect((await verifyAttestationRecord(fair, { superseded: first })).ok).toBe(true);
    const otherGuest = await twoSigned(booking(host.did, stranger.did, { supersedes: sha }), host, stranger);
    expect((await verifyAttestationRecord(otherGuest, { superseded: first })).problems.map((p) => p.code)).toEqual(["SUPERSESSION"]);
  });
  test("a mandate id with no /mandate/ names no principal", () => {
    expect(principalOfMandateId("did:kash:AgencyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/rule/x")).toBeNull();
    expect(principalOfMandateId("did:web:host.example/mandate/app")).toBe("did:web:host.example");
  });
});

describe("two copies of one attestation, shown to two verifiers, share nothing to join on (§3 G1)", () => {
  test("disclosing nothing private, two presentations have no correlator; disclosing the record id links them", async () => {
    const [host, guest] = await Promise.all([party(), party()]);
    const record = await twoSigned(booking(host.did, guest.did), host, guest);
    const make = async (aud: string, disclose: readonly string[]) => {
      const holder = await generateKeyPair();
      const { claims, sdProperties, decoys } = await copyClaimsOf(record, { holderKey: holder.publicKey, iatUnix: 1_795_080_600 });
      const held = await issueSdJwt({ header: { kid: host.did }, claims, sdProperties, decoys, signer: host });
      return presentSdJwt(held, (d) => d.name !== null && disclose.includes(d.name), holder, { aud, nonce: `n-${aud}`, iatUnix: 1_795_080_600 });
    };
    expect(await linkabilityBetween(await make("https://a.example", []), await make("https://b.example", []))).toEqual([]);
    const kinds = (await linkabilityBetween(await make("https://a.example", ["record"]), await make("https://b.example", ["record"]))).map((c) => c.kind);
    expect(kinds).toEqual(["disclosed-value"]);
  });
  test("copies of two records of one class differ only in their keys, digests and signatures — the _sd count says nothing of what each hides", async () => {
    const [host, guest, guest2, guest3] = await Promise.all([party(), party(), party(), party()]);
    const plain = await twoSigned(booking(host.did, guest.did), host, guest);
    const corrected = await twoSigned(booking(host.did, guest2.did, { supersedes: "f".repeat(64) }), host, guest2);
    const withReasons = await twoSigned(booking(host.did, guest3.did, { outcome: "accepted", reasons: ["late-arrival-noted"] }), host, guest3);
    const visibleOf = async (r: DsseEnvelope) => {
      const holder = await generateKeyPair();
      const { claims, sdProperties, decoys } = await copyClaimsOf(r, { holderKey: holder.publicKey, iatUnix: 1_795_080_600 });
      const held = await issueSdJwt({ header: { kid: host.did }, claims, sdProperties, decoys, signer: host });
      const v = decodeJws(parseSdJwt(held)!.issuerJwt)!.payload;
      const { cnf, _sd, ...rest } = v;
      void cnf;
      return { rest, sdCount: (_sd as string[]).length };
    };
    const [a, b, c] = await Promise.all([visibleOf(plain), visibleOf(corrected), visibleOf(withReasons)]);
    expect(b.rest).toEqual(a.rest);
    expect(c.rest).toEqual(a.rest);
    expect([a.sdCount, b.sdCount, c.sdCount]).toEqual([COPY_SD_SLOTS, COPY_SD_SLOTS, COPY_SD_SLOTS]);
  });
  test("no copy carries its record's dates: copies of one record on two days differ; copies of two records on one day agree", async () => {
    const [host, guest, guest2] = await Promise.all([party(), party(), party()]);
    const a = await twoSigned(booking(host.did, guest.did), host, guest);
    const b = await twoSigned(booking(host.did, guest2.did, { expiresAt: "2029-03-07T16:45:12Z" }), host, guest2);
    const k = (await generateKeyPair()).publicKey;
    const day1 = 1_795_046_400;
    const day41 = day1 + 40 * DAY;
    const expOf = async (r: DsseEnvelope, at: number) => (await copyClaimsOf(r, { holderKey: k, iatUnix: at })).claims.exp;
    expect(await expOf(a, day1)).not.toBe(await expOf(a, day41));
    expect(await expOf(a, day1)).toBe(await expOf(b, day1));
  });
  test("a record that ends before a copy's lifetime would gets no copy — a shorter one would carry the record's end", async () => {
    const [host, guest] = await Promise.all([party(), party()]);
    const r = await twoSigned(booking(host.did, guest.did, { claimedAt: "2026-11-02T08:00:00Z", expiresAt: "2027-01-10T12:00:00Z" }), host, guest);
    await expect(copyClaimsOf(r, { holderKey: guest.publicKey, iatUnix: 1_795_046_400 })).rejects.toThrow("the record ends before a copy's lifetime would");
  });
});

interface TckFile<V> {
  readonly lexicon: string;
  readonly cases: readonly { readonly name: string; readonly valid: V; readonly faults?: readonly string[]; readonly body: unknown }[];
}

describe("the conformance cases (specs/attestation/tck)", () => {
  const run = (file: TckFile<boolean>, check: (b: unknown) => { ok: boolean; faults: readonly { code: string }[] }) => {
    for (const c of file.cases) {
      test(`${file.lexicon} · ${c.name}`, () => {
        const r = check(c.body);
        expect(r.ok).toBe(c.valid);
        expect([...new Set(r.faults.map((f) => f.code))].sort()).toEqual([...(c.faults ?? [])].sort());
      });
    }
  };
  const att = readJson<TckFile<boolean>>(TCK, "kash.attestation@1.0.0", "cases.json");
  const man = readJson<TckFile<boolean>>(TCK, "kash.mandate@1.0.0", "cases.json");
  test("each file names its lexicon, and every fault code the rules can raise is exercised", () => {
    expect(att.lexicon).toBe(KASH_ATTESTATION_ID);
    expect(man.lexicon).toBe(KASH_MANDATE_ID);
    const used = (f: TckFile<boolean>) => [...new Set(f.cases.flatMap((c) => c.faults ?? []))].sort();
    expect(used(att)).toEqual(
      [
        "SHAPE", "OUTCOME_FOR_KIND", "REFERENCE_FOR_KIND", "PUBLIC_REFERENCE", "PRIVATE_REFERENCE_ID", "REASONS", "CONTESTS", "COUNTERPARTY_FOR_KIND", "COUNTERPARTY_IS_ISSUER",
        "COUNTERPARTY_WEB", "COUNTERPARTY_MANDATE", "GRADE_REQUIRED", "GRADE_WITHOUT_COUNTERPARTY", "GRADE_ZERO_PRACTICE", "DATES", "MANDATE_PRINCIPAL", "PERSON_IDENTITY",
      ].sort(),
    );
    expect(used(man)).toEqual(["SHAPE", "ID_PRINCIPAL", "DELEGATE_IS_PRINCIPAL", "SCOPE_EMPTY", "MACHINE_REFUSAL", "AGENT_SCOPE", "DESK_DECIDES_ONLY", "DATES", "PERSON_IDENTITY"].sort());
  });
  run(att, checkAttestation);
  run(man, checkMandate);
});

describe("the published JSON Schemas stay in step with the definitions", () => {
  const published = (name: string) => readJson(SPECS, "schemas", name);
  test("attestation.schema.json", () => {
    expect(published("attestation.schema.json")).toEqual(JSON.parse(JSON.stringify(getSchemaDefinition(KASH_ATTESTATION_ID, new LexiconRegistry().register(KASH_ATTESTATION_LEXICON)))));
  });
  test("mandate.schema.json", () => {
    expect(published("mandate.schema.json")).toEqual(JSON.parse(JSON.stringify(getSchemaDefinition(KASH_MANDATE_ID, new LexiconRegistry().register(KASH_MANDATE_LEXICON)))));
  });
  test("attestation-vc.schema.json", () => {
    expect(published("attestation-vc.schema.json")).toEqual(JSON.parse(JSON.stringify(attestationVcJsonSchema())));
  });
});

describe("the registry rows (append-only, d59)", () => {
  test("the record of truth and the mandate are DSSE types, the copy an SD-JWT VC type", () => {
    expect(lookupDst(ATTESTATION_DST)?.family).toBe("dsse-type");
    expect(lookupDst(MANDATE_DST)?.family).toBe("dsse-type");
    expect(lookupDst(ATTESTATION_VCT)?.family).toBe("sd-jwt-vct");
  });
});
