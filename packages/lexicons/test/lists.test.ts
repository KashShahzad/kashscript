/**
 * The trust list and the status list as public records (KS-N1; ECOSYSTEM d47(e), d62(d)5, d91(d), (f)):
 * attest's payloads in clear, the trust list with the three assertions, and the rule that a suspended or
 * removed entry ends its window.
 */

import { describe, expect, test } from "bun:test";
import { validateBody } from "../src/engine";
import { LexiconRegistry } from "../src/registry";
import { validate } from "../src/schema";
import {
  KASH_STATUS_LIST_1_1_BODY_SCHEMA,
  KASH_STATUS_LIST_1_1_ID,
  KASH_STATUS_LIST_BODY_SCHEMA,
  KASH_STATUS_LIST_ID,
  KASH_TRUST_LIST_ID,
  LIST_LEXICONS,
  STATUS_LIST_FORMAT,
  STATUS_PURPOSES,
  TRUST_LIST_FORMAT,
  statusListFaults,
  trustListFaults,
  type StatusListBody,
  type TrustListBody,
  type TrustListIssuer,
} from "../src/extensions/lists";

const registry = new LexiconRegistry().registerAll(LIST_LEXICONS);
const PUB = "did:kash:21UhTqUdjZYWvw3jPz5emqdYskRqdQBLofo3MupZN3Jt";
const ISSUER = "did:kash:7Yq9mKpR3vXsN2bLtH8wJcA4dFgE6uZiVnTkQoPrSxWy";
const NOW = 1_763_251_200; // 2026-11-16T00:00:00Z
const DAY = 86_400;

const ok = (id: string, body: unknown) => {
  const r = validateBody(id, body, registry);
  return r.ok ? [] : r.errors;
};
const refused = (id: string, body: unknown): boolean => !validateBody(id, body, registry).ok;
const codes = (faults: readonly { code: string }[]) => faults.map((f) => f.code);

const listed: TrustListIssuer = {
  issuerId: ISSUER,
  label: "A workshop (sample)",
  keys: [],
  dsts: ["application/vnd.oreoasis.work-record+json"],
  validFromUnix: NOW - DAY,
  validUntilUnix: NOW + 365 * DAY,
  class: "self-issuer",
  standing: "listed",
  grade: 1,
  references: [{ id: `${PUB}/rule/signed-down-the-chain`, hash: "b".repeat(64) }],
};

const removed: TrustListIssuer = {
  issuerId: "assessor-7",
  label: "An assessor that left (sample)",
  keys: [{ keyid: "assessor-7#k1", alg: "ES256", publicKeyHex: `02${"c".repeat(64)}` }],
  dsts: ["application/vnd.oreoasis.predicate+json"],
  validFromUnix: NOW - 400 * DAY,
  validUntilUnix: NOW - 30 * DAY,
  class: "assessor",
  standing: "removed",
  floor: { version: "VISION §4 draft, 2026-10-18" },
};

const trust: TrustListBody = {
  format: TRUST_LIST_FORMAT,
  listId: "ecosystem-issuers",
  version: 3,
  publisher: PUB,
  issuedAtUnix: NOW,
  validFromUnix: NOW,
  validUntilUnix: NOW + 90 * DAY,
  floor: { version: "VISION §4 draft, 2026-10-18" },
  issuers: [listed, removed],
  practice: true,
};

const status: StatusListBody = {
  format: STATUS_LIST_FORMAT,
  type: "BitstringStatusList",
  id: "https://lists.example/status/work-records/2026-q4",
  issuer: ISSUER,
  statusPurpose: "revocation",
  encodedList: `u${"A".repeat(40)}`,
  issuedAtUnix: NOW,
  validUntilUnix: null,
  ttl: 3_600_000,
};

describe("kash.trust-list@1.0.0 — attest's payload, in clear, with d91's three assertions", () => {
  test("a list with a listed self-issuer and a removed assessor has the shape", () => {
    expect(ok(KASH_TRUST_LIST_ID, trust)).toEqual([]);
    expect(trustListFaults(trust)).toEqual([]);
  });
  test("its format is attest's, unchanged — a checker that knows kashscript-trust-list/1 reads it", () => {
    expect(TRUST_LIST_FORMAT).toBe("kashscript-trust-list/1");
    expect(refused(KASH_TRUST_LIST_ID, { ...trust, format: "kashscript-trust-list/2" })).toBe(true);
  });
  test("identity, standing and scope are required on every entry, and the floor on the list", () => {
    const { class: _c, ...noClass } = listed;
    const { standing: _s, ...noStanding } = listed;
    const { dsts: _d, ...noScope } = listed;
    const { floor: _f, ...noFloor } = trust;
    expect(refused(KASH_TRUST_LIST_ID, { ...trust, issuers: [noClass] })).toBe(true);
    expect(refused(KASH_TRUST_LIST_ID, { ...trust, issuers: [noStanding] })).toBe(true);
    expect(refused(KASH_TRUST_LIST_ID, { ...trust, issuers: [noScope] })).toBe(true);
    expect(refused(KASH_TRUST_LIST_ID, { ...trust, issuers: [{ ...listed, dsts: [] }] })).toBe(true);
    expect(refused(KASH_TRUST_LIST_ID, noFloor)).toBe(true);
  });
  test("the classes are d91(f)'s five and the standings its three; the grade is 0 to 3", () => {
    expect(refused(KASH_TRUST_LIST_ID, { ...trust, issuers: [{ ...listed, class: "platform" }] })).toBe(true);
    expect(refused(KASH_TRUST_LIST_ID, { ...trust, issuers: [{ ...listed, standing: "trusted" }] })).toBe(true);
    expect(refused(KASH_TRUST_LIST_ID, { ...trust, issuers: [{ ...listed, grade: 4 }] })).toBe(true);
  });
  test("the shape is closed: no score for an issuer, no person", () => {
    expect(refused(KASH_TRUST_LIST_ID, { ...trust, issuers: [{ ...listed, score: 0.97 }] })).toBe(true);
    expect(refused(KASH_TRUST_LIST_ID, { ...trust, issuers: [{ ...listed, contact: "amina@workshop.example" }] })).toBe(true);
    expect(refused(KASH_TRUST_LIST_ID, { ...trust, issuers: [{ ...listed, keys: [{ keyid: "k", alg: "RSA", publicKeyHex: "ff" }] }] })).toBe(true);
  });
  test("a suspended or removed entry ends its window no later than the list's issuedAtUnix", () => {
    const stillOpen = { ...removed, validUntilUnix: NOW + DAY };
    expect(codes(trustListFaults({ ...trust, issuers: [listed, stillOpen] }))).toEqual(["STANDING_WINDOW"]);
    expect(codes(trustListFaults({ ...trust, issuers: [{ ...listed, standing: "suspended" }] }))).toEqual(["STANDING_WINDOW"]);
    expect(trustListFaults({ ...trust, issuers: [{ ...listed, standing: "suspended", validUntilUnix: NOW }] })).toEqual([]);
  });
  test("windows end after they start", () => {
    expect(codes(trustListFaults({ ...trust, validUntilUnix: NOW - 1 }))).toEqual(["WINDOW"]);
    expect(codes(trustListFaults({ ...trust, issuers: [{ ...listed, validFromUnix: NOW + 2 * DAY, validUntilUnix: NOW + DAY }] }))).toEqual(["WINDOW"]);
  });
});

describe("kash.status-list@1.0.0 — attest's payload, in clear", () => {
  test("a revocation list has the shape", () => {
    expect(ok(KASH_STATUS_LIST_ID, status)).toEqual([]);
    expect(statusListFaults(status)).toEqual([]);
    expect(STATUS_LIST_FORMAT).toBe("kashscript-status-list/1");
  });
  test("1.0.0 admits revocation and suspension, as published; KS-Q4's 1.1.0 adds supersession and withdrawal, and nothing else", () => {
    expect(ok(KASH_STATUS_LIST_ID, { ...status, statusPurpose: "suspension" })).toEqual([]);
    // The registry resolves forward-compatibly (a 1.0.0 record is checked under the newest 1.x), so 1.0.0's own shape is read directly —
    // as a reader still on lexicons 0.5.0 reads it: it refuses the two new purposes, never mis-reads them.
    for (const purpose of ["supersession", "withdrawal", "withdrawn", "superseded", "expired", "refresh"]) {
      expect(validate(KASH_STATUS_LIST_BODY_SCHEMA, { ...status, statusPurpose: purpose }).ok).toBe(false);
    }
    expect(validate(KASH_STATUS_LIST_BODY_SCHEMA, { ...status, statusPurpose: "revocation" }).ok).toBe(true);
    // Every 1.0.0 body is a 1.1.0 body.
    expect(validate(KASH_STATUS_LIST_1_1_BODY_SCHEMA, status).ok).toBe(true);
    expect(STATUS_PURPOSES).toEqual(["revocation", "suspension", "supersession", "withdrawal"]);
    for (const purpose of STATUS_PURPOSES) expect(ok(KASH_STATUS_LIST_1_1_ID, { ...status, statusPurpose: purpose })).toEqual([]);
    // Expiry is the clock's; W3C's refresh does not invalidate, so neither is a purpose here.
    for (const purpose of ["withdrawn", "superseded", "expired", "refresh", "message"]) {
      expect(refused(KASH_STATUS_LIST_1_1_ID, { ...status, statusPurpose: purpose })).toBe(true);
    }
  });
  test("the list is served over https, the bitstring is multibase base64url, and validUntil is a time or null", () => {
    expect(refused(KASH_STATUS_LIST_ID, { ...status, id: "http://lists.example/status/1" })).toBe(true);
    expect(refused(KASH_STATUS_LIST_ID, { ...status, encodedList: "zAAAA" })).toBe(true);
    expect(refused(KASH_STATUS_LIST_ID, { ...status, validUntilUnix: "never" })).toBe(true);
    expect(ok(KASH_STATUS_LIST_ID, { ...status, validUntilUnix: NOW + DAY })).toEqual([]);
  });
  test("the shape is closed — a status list is a bitstring, never a list of records or people", () => {
    expect(refused(KASH_STATUS_LIST_ID, { ...status, revoked: ["rcpt_1", "rcpt_2"] })).toBe(true);
    expect(refused(KASH_STATUS_LIST_ID, { ...status, holders: [] })).toBe(true);
  });
  test("the rules the shape cannot write", () => {
    expect(codes(statusListFaults({ ...status, validUntilUnix: NOW - 1 }))).toEqual(["VALID_UNTIL"]);
  });
});
