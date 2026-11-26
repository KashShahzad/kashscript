/**
 * Education Extension — academia-domain lexicons (Jinnahnook-shaped).
 *
 *   kash.education.transcript@1.0.0       — a course / degree transcript record
 *   kash.education.peer-review@2.0.0      — a peer-review of an academic work
 *   kash.education.peer-review@1.0.0      — read, no longer written (it had a score)
 *
 * Import path: `@kashscript/lexicons/extensions/education`.
 *
 * The Foundry core never auto-loads this extension. Consumers register
 * `EDUCATION_EXTENSION` against their `LexiconRegistry` to opt in to
 * academic-domain validation. Pairs with the Jinnahnook program at
 * `apps/kashscript/app/studio/jinnahnook`.
 */

import type { LexiconDef } from "../registry";
import { S, type ObjectSchema } from "../schema";

/* ─────────────────────────────────────────────────────────────────
 *  kash.education.transcript@1.0.0
 *
 *  Issuer (a registrar / institution) signs one record per
 *  course-or-degree credit awarded to a student. The student holds
 *  their transcript as a collection of these records and can
 *  selectively disclose individual entries via @kashscript/identity-zkp.
 * ───────────────────────────────────────────────────────────────── */

export const KASH_EDU_TRANSCRIPT_NSID    = "kash.education.transcript" as const;
export const KASH_EDU_TRANSCRIPT_VERSION = { major: 1, minor: 0, patch: 0 } as const;
export const KASH_EDU_TRANSCRIPT_ID      = "kash.education.transcript@1.0.0" as const;

export type CreditKind = "course" | "thesis" | "internship" | "lab" | "seminar";

export const KASH_EDU_TRANSCRIPT_BODY_SCHEMA: ObjectSchema = S.object(
  {
    /** DID of the student this transcript entry is about. */
    studentDid: S.string({ format: "did-ks" }),
    /** Stable institutional identifier for the course / unit. */
    courseCode: S.string({ minLength: 1, maxLength: 32, pattern: /^[A-Z0-9][A-Z0-9-]{0,31}$/ }),
    /** Display title — kept separate from courseCode so the wire shape stays stable across rename. */
    courseTitle: S.string({ minLength: 1, maxLength: 200 }),
    /** Kind of credit. */
    kind: S.enum("course", "thesis", "internship", "lab", "seminar"),
    /** Credit units (e.g., 3 for a 3-credit course). */
    credits: S.number({ min: 0, max: 200 }),
    /** Grade — institution-specific letter / score / pass-fail tag. */
    grade: S.string({ minLength: 1, maxLength: 8 }),
    /** ISO date the credit was awarded. */
    awardedAt: S.string({ format: "iso8601" }),
    /** Optional advisor / instructor of record. */
    instructorDid: S.optional(S.string({ format: "did-ks" })),
    /** Optional human-readable notes. */
    notes: S.optional(S.string({ maxLength: 1000 })),
  },
  [
    "studentDid", "courseCode", "courseTitle", "kind", "credits", "grade", "awardedAt",
  ],
);

/* ─────────────────────────────────────────────────────────────────
 *  kash.education.peer-review@1.0.0
 *
 *  A reviewer's signed assessment of an academic work (paper, thesis
 *  chapter, conference submission). Used by Jinnahnook for the peer-
 *  review surface; can be anonymised at disclosure time via ZK.
 * ───────────────────────────────────────────────────────────────── */

export const KASH_EDU_PEER_REVIEW_NSID    = "kash.education.peer-review" as const;
export const KASH_EDU_PEER_REVIEW_VERSION = { major: 1, minor: 0, patch: 0 } as const;
export const KASH_EDU_PEER_REVIEW_ID      = "kash.education.peer-review@1.0.0" as const;

export type ReviewVerdict = "accept" | "minor-revisions" | "major-revisions" | "reject";

export const KASH_EDU_PEER_REVIEW_BODY_SCHEMA: ObjectSchema = S.object(
  {
    /** The work being reviewed — cid of the manuscript, plus title for display. */
    workCid: S.string({ format: "cid" }),
    workTitle: S.string({ minLength: 1, maxLength: 300 }),
    /** Author DID — what selective disclosure later proves out. */
    authorDid: S.string({ format: "did-ks" }),
    /** Optional venue (journal / conference name). */
    venue: S.optional(S.string({ minLength: 1, maxLength: 200 })),
    /** Verdict from the standard four-option ladder. */
    verdict: S.enum("accept", "minor-revisions", "major-revisions", "reject"),
    /** Reviewer's written assessment. */
    body: S.string({ minLength: 1, maxLength: 50_000 }),
    /** Numeric score on the institutional scale. */
    score: S.optional(S.number({ min: 0, max: 10 })),
    /** When the review was finalised. */
    reviewedAt: S.string({ format: "iso8601" }),
  },
  ["workCid", "workTitle", "authorDid", "verdict", "body", "reviewedAt"],
);

/* ─────────────────────────────────────────────────────────────────
 *  kash.education.peer-review@2.0.0
 *
 *  1.0.0 without `score` (RW-18). A number beside the author's DID
 *  rates a person's work, and nothing on the floor scores a person
 *  (d27, d43, d85(b)3). The verdict and the reviewer's words stay.
 *  Write 2.0.0. 1.0.0 stays registered so that a record signed under
 *  it still validates (append-only, d59).
 * ───────────────────────────────────────────────────────────────── */

export const KASH_EDU_PEER_REVIEW_2_0_VERSION = { major: 2, minor: 0, patch: 0 } as const;
export const KASH_EDU_PEER_REVIEW_2_0_ID      = "kash.education.peer-review@2.0.0" as const;

export const KASH_EDU_PEER_REVIEW_2_0_BODY_SCHEMA: ObjectSchema = S.object(
  {
    /** The work being reviewed — cid of the manuscript, plus title for display. */
    workCid: S.string({ format: "cid" }),
    workTitle: S.string({ minLength: 1, maxLength: 300 }),
    /** Author DID — what selective disclosure later proves out. */
    authorDid: S.string({ format: "did-ks" }),
    /** Optional venue (journal / conference name). */
    venue: S.optional(S.string({ minLength: 1, maxLength: 200 })),
    /** Verdict from the standard four-option ladder. */
    verdict: S.enum("accept", "minor-revisions", "major-revisions", "reject"),
    /** Reviewer's written assessment. */
    body: S.string({ minLength: 1, maxLength: 50_000 }),
    /** When the review was finalised. */
    reviewedAt: S.string({ format: "iso8601" }),
  },
  ["workCid", "workTitle", "authorDid", "verdict", "body", "reviewedAt"],
);

/* ─────────────────────────────────────────────────────────────────
 *  Extension bundle
 * ───────────────────────────────────────────────────────────────── */

/** Education-domain lexicons. Pass to `LexiconRegistry.registerAll()`. */
export const EDUCATION_EXTENSION: readonly LexiconDef[] = [
  {
    id: KASH_EDU_TRANSCRIPT_ID,
    nsid: KASH_EDU_TRANSCRIPT_NSID,
    semver: KASH_EDU_TRANSCRIPT_VERSION,
    bodySchema: KASH_EDU_TRANSCRIPT_BODY_SCHEMA,
    title: "Education Transcript Entry",
    description: "A single course / degree credit record signed by the issuing institution.",
  },
  {
    id: KASH_EDU_PEER_REVIEW_ID,
    nsid: KASH_EDU_PEER_REVIEW_NSID,
    semver: KASH_EDU_PEER_REVIEW_VERSION,
    bodySchema: KASH_EDU_PEER_REVIEW_BODY_SCHEMA,
    title: "Academic Peer Review",
    description: "A reviewer's signed assessment of an academic work.",
  },
  {
    id: KASH_EDU_PEER_REVIEW_2_0_ID,
    nsid: KASH_EDU_PEER_REVIEW_NSID,
    semver: KASH_EDU_PEER_REVIEW_2_0_VERSION,
    bodySchema: KASH_EDU_PEER_REVIEW_2_0_BODY_SCHEMA,
    title: "Academic Peer Review",
    description: "A reviewer's signed assessment of an academic work, with a verdict and no score.",
  },
];
