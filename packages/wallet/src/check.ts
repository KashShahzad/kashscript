/**
 * Check — anyone's receipt, free, offline (d27.4; d42 §2: "check anyone
 * else's receipt, free"). attest does every check; this turns its report into
 * plain words, and keeps the report itself beside them so a surface can draw
 * a "signed by both" mark only from a real verification result (d51(g)).
 *
 * A tick is never alone (d51 law 9): every result says who signed, and what
 * the check does NOT prove.
 */

import { makeKeyResolver, type HeldArtifact, type HeldRecordContext, type HeldRecordReport, type StatusVerdict } from "@kashscript/attest/holder";
import { fill } from "./copy";
import type { WalletCore } from "./core";
import { WalletError } from "./errors";
import { detectKind, hardFailures, probeArtifact, signedPayloadOf } from "./records";

export type CheckState = "signed-by-both" | "one-signature" | "signed" | "device-only" | "doesnt-match" | "expired";

export interface CheckResult {
  readonly state: CheckState;
  readonly practice: boolean;
  /** One sentence for the state, plus one for the signer's listing. */
  readonly words: readonly string[];
  /** What this check does not prove. Always present. */
  readonly notProven: string;
  readonly signer: string | null;
  readonly listed: boolean;
  /** The status verdict, in attest's words, naming its time — or saying it wasn't checked. */
  readonly status: StatusVerdict;
  /** attest's own report. The only thing a "signed by both" mark may be drawn from. */
  readonly report: HeldRecordReport;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const PRACTICE = /^practice\b/i;

/**
 * A practice artifact says so inside what its signer signed (d11): a
 * `practice` field, or — where a format has no room for one — a signed name
 * that begins with "practice" (a predicate's kind or rule, a session's id, a
 * thank-you's text).
 */
export function isPractice(artifact: HeldArtifact, payload: unknown): boolean {
  if (artifact.kind === "session-receipt") return isPlainObject(artifact.value) && typeof artifact.value.sessionId === "string" && PRACTICE.test(artifact.value.sessionId);
  if (!isPlainObject(payload)) return false;
  if (payload.practice === true) return true;
  const p = isPlainObject(payload.predicate) ? payload.predicate : null;
  if (p !== null && (PRACTICE.test(String(p.kind)) || (isPlainObject(p.rule) && PRACTICE.test(String(p.rule.id))))) return true;
  return typeof payload.value === "string" && PRACTICE.test(payload.value);
}

export async function checkArtifact(core: WalletCore, value: unknown): Promise<CheckResult> {
  const kind = detectKind(value);
  if (kind === null) throw new WalletError("REQUEST_INVALID", "not an artifact the checker knows");
  const artifact: HeldArtifact = { kind, value: typeof value === "string" ? value.trim() : value };
  // Uses the trust lists and status lists the wallet carries when it is
  // unlocked; locked, it still checks everything that needs no list.
  const ctx: HeldRecordContext = core.vault.unlocked
    ? await core.trust.context()
    : { resolveKey: makeKeyResolver(new Map(), new Map()), trustLists: [], statusLists: [], revocations: [], nowSec: core.now(), exportedAtUnix: null };
  const report = await probeArtifact(artifact, ctx);
  const c = core.copy;
  const listed = report.listing.evidence === "pinned-list";
  const name = report.listing.label ?? report.issuer ?? "";
  const payload = signedPayloadOf(artifact);

  let state: CheckState;
  let notProven: string;
  if (hardFailures(report).length > 0) {
    state = "doesnt-match";
    notProven = c.notProvenOneSignature;
  } else if (report.retention.pastNow || (isPlainObject(payload) && typeof payload.exp === "number" && payload.exp <= core.now())) {
    state = "expired";
    notProven = c.notProvenSigned;
  } else if (report.attestation === "countersigned") {
    state = "signed-by-both";
    notProven = c.notProvenCountersigned;
  } else if (report.attestation === "device-asserted") {
    state = "device-only";
    notProven = c.notProvenDeviceOnly;
  } else if (kind === "session-receipt") {
    state = "one-signature";
    notProven = c.notProvenOneSignature;
  } else {
    state = "signed";
    notProven = c.notProvenSigned;
  }
  const stateWords: Record<CheckState, string> = {
    "signed-by-both": c.checkSignedByBoth,
    "one-signature": c.checkOneSignature,
    signed: fill(c.checkSigned, { name }),
    "device-only": c.checkDeviceOnly,
    "doesnt-match": c.checkDoesntMatch,
    expired: c.checkExpired,
  };
  const words = [stateWords[state], listed ? fill(c.checkListed, { name }) : c.checkUnlisted];
  const practice = isPractice(artifact, payload);
  if (practice) words.push(c.checkPractice);
  return { state, practice, words, notProven, signer: report.issuer, listed, status: report.status, report };
}
