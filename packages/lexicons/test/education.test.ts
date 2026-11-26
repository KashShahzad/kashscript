/**
 * The education vocabulary: peer review 2.0.0 carries no score (RW-18), and a record signed under 1.0.0 still reads
 * (append-only, d59).
 */

import { describe, expect, test } from "bun:test";
import { validateBody } from "../src/engine";
import { LexiconRegistry } from "../src/registry";
import {
  EDUCATION_EXTENSION,
  KASH_EDU_PEER_REVIEW_2_0_BODY_SCHEMA,
  KASH_EDU_PEER_REVIEW_2_0_ID,
  KASH_EDU_PEER_REVIEW_ID,
} from "../src/extensions/education";

const registry = new LexiconRegistry().registerAll(EDUCATION_EXTENSION);

const review = {
  workCid: `bafy${"a".repeat(55)}`,
  workTitle: "On records that expire",
  authorDid: "did:kash:21UhTqUdjZYWvw3jPz5emqdYskRqdQBLofo3MupZN3Jt",
  verdict: "minor-revisions",
  body: "Sound; the second section needs its sources.",
  reviewedAt: "2026-11-27T00:00:00Z",
};

describe("kash.education.peer-review@2.0.0", () => {
  test("has no score", () => {
    expect(Object.keys(KASH_EDU_PEER_REVIEW_2_0_BODY_SCHEMA.properties)).not.toContain("score");
  });
  test("accepts a review that says its verdict in words", () => {
    expect(validateBody(KASH_EDU_PEER_REVIEW_2_0_ID, review, registry).ok).toBe(true);
  });
  test("refuses a score", () => {
    expect(validateBody(KASH_EDU_PEER_REVIEW_2_0_ID, { ...review, score: 7 }, registry).ok).toBe(false);
  });
  test("leaves a record signed under 1.0.0 readable", () => {
    expect(validateBody(KASH_EDU_PEER_REVIEW_ID, { ...review, score: 7 }, registry).ok).toBe(true);
  });
});
