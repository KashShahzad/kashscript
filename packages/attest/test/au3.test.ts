/**
 * AU-3 (AUDIT-2026-11-11, A7-01 to A7-08): the verifier reports only what it verified.
 *
 * The cases that do not sit beside one module's own tests: the DSSE envelope that
 * never throws on untrusted input, a record's one content identity, the audit
 * bundle whose only key came from inside the file, a holder export with one
 * malformed record among good ones, and the committed vectors under
 * test/vectors/au3 (generated once; each is a forgery or a re-wrapping the
 * verifier must refuse by name).
 */

import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { deriveDid, generateKeyPair, signEvent } from "@kashscript/identity-core";
import { AttestError } from "../src/errors";
import { verifyAuditBundle } from "../src/bundle";
import { pae, signEnvelope, verifyEnvelope, type DsseEnvelope } from "../src/dsse";
import { base64ToBytes, bytesToBase64, signRaw } from "../src/ed25519";
import { contentIdOf, makeKeyResolver, recordIdOf, verifyHeldRecord, verifyHolderExport, type HeldRecord, type HolderExport, type HoldingManifest } from "../src/holder";
import { verifyCountersignBundle, type CountersignBundle } from "../src/countersign";
import { resolveDidKey } from "../src/signing";

const TYPE = "application/vnd.example.thing+json";
const FIXTURES = join(import.meta.dir, "fixtures");
const VECTORS = join(import.meta.dir, "vectors");
const readJson = <T,>(dir: string, name: string): T => JSON.parse(readFileSync(join(dir, name), "utf8")) as T;
const noKeys = makeKeyResolver(new Map(), new Map());

async function signer() {
  const kp = await generateKeyPair();
  return { ...kp, did: deriveDid(kp.publicKey) };
}

/** A manifest that claims nothing, so only the artifact's own analysis is under test. */
const probe = (): HoldingManifest => ({
  recordId: "",
  issuer: "",
  relationship: null,
  type: { tag: "", family: "dsse-type", attestation: "issuer-signed" },
  receivedAtUnix: 0,
  expiresAtUnix: null,
  retentionSource: "none-declared",
  status: null,
  listing: "unlisted",
  keptUnlistedAtUnix: 0,
});
const heldCtx = { resolveKey: noKeys, trustLists: [], statusLists: [], revocations: [], nowSec: 1_790_000_000, exportedAtUnix: null };

/* ── A7-04: the envelope verifier never throws on what anyone can append ─── */

describe("dsse — untrusted input is reported, never thrown (A7-04)", () => {
  it("a sibling signature that is not base64 is skipped; the valid signature beside it still verifies", async () => {
    const s = await signer();
    const env = await signEnvelope({ a: 1 }, TYPE, { keyid: s.did, privateKey: s.privateKey, publicKey: s.publicKey }, { canonical: true });
    const junk: DsseEnvelope = { ...env, signatures: [...env.signatures, { keyid: "x", sig: "%%%" }, { keyid: s.did, sig: "%%%" }] };
    const r = await verifyEnvelope(junk, (k) => resolveDidKey(k));
    expect(r.ok).toBe(true);
    expect(r.verifiedKeyids).toEqual([s.did]);
  });

  it("a payload that is not JSON is reported as such — the signature verdict stands, the payload reads as undefined", async () => {
    const s = await signer();
    const bytes = new TextEncoder().encode("not json");
    const sig = await signRaw(pae(TYPE, bytes), s.privateKey, s.publicKey);
    const raw: DsseEnvelope = { payloadType: TYPE, payload: bytesToBase64(bytes), signatures: [{ keyid: s.did, sig: bytesToBase64(sig) }] };
    const r = await verifyEnvelope(raw, (k) => resolveDidKey(k));
    expect(r.ok).toBe(true);
    expect(r.payloadJson).toBeUndefined();
    // and the holder layer calls such a record malformed, without throwing
    const report = await verifyHeldRecord({ manifest: probe(), artifact: { kind: "dsse", value: raw } }, heldCtx);
    expect(report.reasons).toContain("MALFORMED_ARTIFACT");
  });

  it("the audit-bundle verifier refuses a non-JSON payload by name, not with a TypeError", async () => {
    const s = await signer();
    const bytes = new TextEncoder().encode("not json");
    const sig = await signRaw(pae("application/vnd.oreoasis.audit-bundle+json", bytes), s.privateKey, s.publicKey);
    const env: DsseEnvelope = { payloadType: "application/vnd.oreoasis.audit-bundle+json", payload: bytesToBase64(bytes), signatures: [{ keyid: s.did, sig: bytesToBase64(sig) }] };
    await expect(verifyAuditBundle(env)).rejects.toBeInstanceOf(AttestError);
  });

  it("a held countersign bundle with a junk sibling signature verifies; a holder export with one malformed record still judges the rest", async () => {
    const fixture = readJson<CountersignBundle>(FIXTURES, "countersign-bundle.json");
    const withJunk = { ...fixture, subject: { ...fixture.subject, signatures: [...fixture.subject.signatures, { keyid: "x", sig: "%%%" }] } };
    const one = await verifyHeldRecord({ manifest: probe(), artifact: { kind: "countersign-bundle", value: withJunk } }, heldCtx);
    expect(one.signatureOk).toBe(true);
    expect(one.reasons).not.toContain("MALFORMED_ARTIFACT");

    const exp = JSON.parse(readFileSync(join(VECTORS, "holder", "holder-export.v1.json"), "utf8")) as HolderExport;
    const dsseRecord = exp.records.find((r) => r.artifact.kind === "dsse")!;
    const broken: HeldRecord = {
      manifest: { ...dsseRecord.manifest, recordId: "f".repeat(64) },
      artifact: { kind: "dsse", value: { ...(dsseRecord.artifact.value as DsseEnvelope), payload: bytesToBase64(new TextEncoder().encode("not json")) } },
    };
    const report = await verifyHolderExport({ ...exp, records: [...exp.records, broken] }, { nowSec: exp.exportedAtUnix });
    expect(report.records).toHaveLength(exp.records.length + 1);
    expect(report.records.filter((r) => r.reasons.includes("MALFORMED_ARTIFACT"))).toHaveLength(1);
    expect(report.records.filter((r) => r.ok)).toHaveLength(exp.records.length);
    expect(report.ok).toBe(false);
  });
});

/* ── A7-02: the holder layer counts keys, not spellings ──────────────────── */

describe("holder — a DSSE record signed twice by one key under two spellings is one signer (A7-02)", () => {
  it("names no second signature where there is one key", async () => {
    const s = await signer();
    const env = await signEnvelope({ a: 1 }, TYPE, { keyid: s.did, privateKey: s.privateKey, publicKey: s.publicKey }, { canonical: true });
    const twice: DsseEnvelope = { ...env, signatures: [...env.signatures, { keyid: `${s.did}#c`, sig: env.signatures[0]!.sig }] };
    const report = await verifyHeldRecord({ manifest: probe(), artifact: { kind: "dsse", value: twice } }, heldCtx);
    expect(report.signatureOk).toBe(true);
    expect(report.notes.join(" ")).not.toContain("two signatures");
  });
});

/* ── A7-03: one content identity for counting ────────────────────────────── */

describe("holder — a record has one content identity, whatever wraps it (A7-03)", () => {
  it("a DSSE record and its countersigned form share it; a re-wrapped copy changes the record id and not the content id", async () => {
    const s = await signer();
    const env = await signEnvelope({ a: 1 }, TYPE, { keyid: s.did, privateKey: s.privateKey, publicKey: s.publicKey }, { canonical: true });
    const asBundle = { formatVersion: "kashscript-countersign/1", subject: env, request: { header: {}, body: {}, signature: {} }, acceptances: [] };
    const rewrapped = { ...asBundle, _: 1 };
    const withJunk = { ...asBundle, subject: { ...env, signatures: [...env.signatures, { keyid: "did:kash:Z", sig: "AAAA" }] } };
    const dsseId = await contentIdOf({ kind: "dsse", value: env });
    expect(await contentIdOf({ kind: "countersign-bundle", value: asBundle })).toBe(dsseId);
    expect(await contentIdOf({ kind: "countersign-bundle", value: rewrapped })).toBe(dsseId);
    expect(await contentIdOf({ kind: "countersign-bundle", value: withJunk })).toBe(dsseId);
    const ids = await Promise.all([asBundle, rewrapped, withJunk].map((v) => recordIdOf({ kind: "countersign-bundle", value: v })));
    expect(new Set(ids).size).toBe(3);
    expect(dsseId).not.toBe(ids[0]);
  });

  it("a Kash-Event's identity is its header and body — the signature's own encoding is not part of it", async () => {
    const s = await signer();
    const header = { typ: "x", v: 1 };
    const body = { b: 2 };
    const a = { header, body, signature: await signEvent(header, body, s.privateKey) };
    const b = { header, body, signature: await signEvent(header, body, s.privateKey, { encoding: "hex" }) };
    expect(await contentIdOf({ kind: "kash-event", value: a })).toBe(await contentIdOf({ kind: "kash-event", value: b }));
    expect(await recordIdOf({ kind: "kash-event", value: a })).not.toBe(await recordIdOf({ kind: "kash-event", value: b }));
  });

  it("an SD-JWT's identity is its issuer-signed JWT, as its record id already was", async () => {
    const held = readFileSync(join(VECTORS, "exchange", "predicate-held-a.v1.txt"), "utf8").trim();
    const issuerJwt = held.split("~")[0]!;
    expect(await contentIdOf({ kind: "sd-jwt", value: held })).toBe(await recordIdOf({ kind: "sd-jwt", value: issuerJwt }));
  });
});

/* ── A7-06: a key that came from inside the file is self-asserted ────────── */

describe("audit bundle — a key from inside the file proves integrity only (A7-06)", () => {
  it("says so in the report, and stops saying so once a trusted key is supplied", async () => {
    const env = readJson<DsseEnvelope>(FIXTURES, "oreoasis-audit-bundle.dsse.json");
    const fromFile = await verifyAuditBundle(env);
    expect(fromFile.ok).toBe(true); // the chain and the envelope are consistent with themselves
    expect(fromFile.selfAsserted).toBe(true);
    const named = await verifyAuditBundle(env, { requireSignerDid: env.signatures[0]!.keyid });
    expect(named.selfAsserted).toBe(true); // naming a DID that is also in the file is no trust
    const hex = readFileSync(join(FIXTURES, "oreoasis-host-public-key.txt"), "utf8").trim().split(/\s+/).pop()!;
    const trusted = await verifyAuditBundle(env, { trustedKeysByDid: new Map([[env.signatures[0]!.keyid, hex]]), requireSignerDid: env.signatures[0]!.keyid });
    expect(trusted.ok).toBe(true);
    expect(trusted.selfAsserted).toBe(false);
  });
});

/* ── the committed vectors ───────────────────────────────────────────────── */

describe("the AU-3 vectors — each forgery and re-wrapping is refused by name", () => {
  const dir = join(VECTORS, "au3");
  const expected = readJson<Record<string, { readonly kind: "sd-jwt" | "countersign"; readonly reason: string | null; readonly independentSignatureCount?: number; readonly countersigners?: readonly string[]; readonly audience?: string; readonly nonce?: string; readonly nowSec: number }>>(dir, "expected.v1.json");
  const ctx = readJson<{ readonly listedKeyid: string; readonly listedPublicKeyHex: string }>(dir, "context.v1.json");

  for (const [file, want] of Object.entries(expected)) {
    it(`${file} → ${want.reason ?? "ok"}`, async () => {
      if (want.kind === "sd-jwt") {
        const { verifySdJwt } = await import("../src/sd-jwt");
        const { hexToBytes } = await import("../src/chain");
        const resolveKey = makeKeyResolver(new Map([[ctx.listedKeyid, { publicKey: hexToBytes(ctx.listedPublicKeyHex), pinned: true }]]), new Map());
        const r = await verifySdJwt(readFileSync(join(dir, file), "utf8").trim(), {
          resolveKey,
          requireKeyBinding: want.audience !== undefined,
          nowSec: want.nowSec,
          ...(want.audience !== undefined ? { audience: want.audience, nonce: want.nonce } : {}),
        });
        expect(r.reason).toBe(want.reason as never);
        expect(r.ok).toBe(want.reason === null);
      } else {
        const r = await verifyCountersignBundle(readJson<CountersignBundle>(dir, file));
        expect(r.reason).toBe(want.reason as never);
        expect(r.ok).toBe(want.reason === null);
        if (want.independentSignatureCount !== undefined) expect(r.independentSignatureCount).toBe(want.independentSignatureCount);
        if (want.countersigners !== undefined) {
          expect(r.acceptances.filter((a) => a.ok && a.independent).map((a) => a.countersignerDid)).toEqual([...want.countersigners]);
        }
      }
    });
  }
});

/* ── the bundle verifier's own never-throws promise, on the vectors' shapes ── */

describe("countersign — the never-throws promise holds for a non-base64 sibling and a non-JSON subject (A7-04)", () => {
  it("returns a report for both", async () => {
    const fixture = readJson<CountersignBundle>(FIXTURES, "countersign-bundle.json");
    const junk = await verifyCountersignBundle({ ...fixture, subject: { ...fixture.subject, signatures: [...fixture.subject.signatures, { keyid: "x", sig: "%%%" }] } });
    expect(junk.ok).toBe(true);
    const bytes = base64ToBytes(fixture.subject.payload);
    expect(bytes.length).toBeGreaterThan(0);
  });
});
