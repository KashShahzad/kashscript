/**
 * The presentation log — the holder's own record of what they showed, to whom
 * (d42 §2: "log every presentation the holder made and to whom";
 * specs/presentation.md §4). Holder-side and exportable in the holder export;
 * **never sent anywhere**, and not part of any presentation.
 *
 * Two kinds only. A **presentation** the holder made, and an **excessive-ask
 * note** — the holder's own record that an ask asked too much (rule 7), made
 * only if the holder chooses to. **A decline has no format**: declining an ask
 * emits nothing, to anyone, and the log has no entry for it (d49(a)).
 */

import { sha256Hex } from "../chain";
import { parseSdJwt } from "../sd-jwt/sd-jwt";
import type { AskRule } from "./ask";

export const PRESENTATION_LOG_FORMAT = "kashscript-presentation-log/1" as const;

export interface AskRef {
  readonly key: string;
  readonly version: number;
  readonly sha256: string;
}

export interface PresentationEntry {
  readonly kind: "presentation";
  readonly atUnix: number;
  /** The audience the presentation was bound to. */
  readonly verifier: string;
  /** The relationship identifier the holder presented under — fresh per verifier. */
  readonly relationship: string;
  readonly ask: AskRef | null;
  /** Local digests of the issued copies shown (see `credentialCopySha256`). */
  readonly credentials: readonly { readonly vct: string; readonly copySha256: string }[];
  /** Which disclosures the holder chose, e.g. `restsOn[1]`. */
  readonly disclosed: readonly string[];
  readonly attachedRecordIds: readonly string[];
  /** The holder deliberately linked this presentation to an earlier one (rule 6). */
  readonly linkedByHolder: boolean;
}

export interface ExcessiveAskNote {
  readonly kind: "excessive-ask";
  readonly atUnix: number;
  readonly ask: AskRef;
  /** The rules the holder believes the ask breaks. */
  readonly rules: readonly AskRule[];
  readonly note: string | null;
}

export type PresentationLogEntry = PresentationEntry | ExcessiveAskNote;

export type PresentationLogViolation =
  | "NOT_A_LIST"
  | "DECLINE_HAS_NO_FORMAT"
  | "UNKNOWN_KIND"
  | "MALFORMED_ENTRY"
  | "UNKNOWN_FIELD"
  | "COPY_REUSED_ACROSS_VERIFIERS"
  | "RELATIONSHIP_REUSED_ACROSS_VERIFIERS";

const PRESENTATION_KEYS = ["kind", "atUnix", "verifier", "relationship", "ask", "credentials", "disclosed", "attachedRecordIds", "linkedByHolder"];
const NOTE_KEYS = ["kind", "atUnix", "ask", "rules", "note"];

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
const isInt = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v);
const isStrList = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string");
function isAskRef(v: unknown): v is AskRef {
  return isPlainObject(v) && typeof v.key === "string" && isInt(v.version) && typeof v.sha256 === "string";
}

/** A local digest naming one issued copy — SHA-256 of its issuer JWT. */
export async function credentialCopySha256(sdJwt: string): Promise<string> {
  const p = parseSdJwt(sdJwt);
  if (p === null) throw new Error("not an SD-JWT");
  return sha256Hex(new TextEncoder().encode(p.issuerJwt));
}

/**
 * Validate a log. Beyond shape, it enforces rule 6 from the holder's side: an
 * issued copy, or a relationship key, shown to a second verifier is a link —
 * allowed only where the holder marked it as theirs to make.
 */
export function validatePresentationLog(entries: unknown): {
  readonly ok: boolean;
  readonly violations: readonly { readonly index: number; readonly code: PresentationLogViolation; readonly message: string }[];
} {
  const v: { index: number; code: PresentationLogViolation; message: string }[] = [];
  if (!Array.isArray(entries)) return { ok: false, violations: [{ index: -1, code: "NOT_A_LIST", message: "the log is a list" }] };
  const copyVerifier = new Map<string, string>();
  const relVerifier = new Map<string, string>();
  entries.forEach((e, index) => {
    if (!isPlainObject(e)) {
      v.push({ index, code: "MALFORMED_ENTRY", message: "an entry is an object" });
      return;
    }
    const kind = e.kind;
    if (typeof kind === "string" && /declin|refus|reject|no-answer/i.test(kind)) {
      v.push({ index, code: "DECLINE_HAS_NO_FORMAT", message: "a decline emits nothing, and the log records nothing for it" });
      return;
    }
    if (kind === "presentation") {
      for (const k of Object.keys(e)) if (!PRESENTATION_KEYS.includes(k)) v.push({ index, code: "UNKNOWN_FIELD", message: `"${k}" is not part of a log entry` });
      if (
        !isInt(e.atUnix) ||
        typeof e.verifier !== "string" ||
        typeof e.relationship !== "string" ||
        !(e.ask === null || isAskRef(e.ask)) ||
        !Array.isArray(e.credentials) ||
        !e.credentials.every((c) => isPlainObject(c) && typeof c.vct === "string" && typeof c.copySha256 === "string") ||
        !isStrList(e.disclosed) ||
        !isStrList(e.attachedRecordIds) ||
        typeof e.linkedByHolder !== "boolean"
      ) {
        v.push({ index, code: "MALFORMED_ENTRY", message: "a presentation entry is malformed" });
        return;
      }
      const verifier = e.verifier;
      for (const c of e.credentials as { copySha256: string }[]) {
        const first = copyVerifier.get(c.copySha256);
        if (first !== undefined && first !== verifier && !e.linkedByHolder) {
          v.push({ index, code: "COPY_REUSED_ACROSS_VERIFIERS", message: "one issued copy shown to two verifiers links them — use a fresh copy per verifier" });
        }
        if (first === undefined) copyVerifier.set(c.copySha256, verifier);
      }
      const firstRel = relVerifier.get(e.relationship);
      if (firstRel !== undefined && firstRel !== verifier && !e.linkedByHolder) {
        v.push({ index, code: "RELATIONSHIP_REUSED_ACROSS_VERIFIERS", message: "one relationship key shown to two verifiers links them" });
      }
      if (firstRel === undefined) relVerifier.set(e.relationship, verifier);
      return;
    }
    if (kind === "excessive-ask") {
      for (const k of Object.keys(e)) if (!NOTE_KEYS.includes(k)) v.push({ index, code: "UNKNOWN_FIELD", message: `"${k}" is not part of a note` });
      if (!isInt(e.atUnix) || !isAskRef(e.ask) || !isStrList(e.rules) || !(e.note === null || typeof e.note === "string")) {
        v.push({ index, code: "MALFORMED_ENTRY", message: "an excessive-ask note is malformed" });
      }
      return;
    }
    v.push({ index, code: "UNKNOWN_KIND", message: "a log holds presentations and excessive-ask notes only" });
  });
  return { ok: v.length === 0, violations: v };
}
