/**
 * The time verdict (KS-Q4; ECOSYSTEM d91(a): time comes from a witness, never
 * from the signer; d91(i): a receipt issued before the log began carries a
 * witness dated when it was anchored, never backdated, and the page says so).
 *
 * Three times meet here and are never confused:
 *   • **claimed** — what the entry's author wrote (an issuer's clock);
 *   • **the log's claim** — the checkpoint's own `timestampUnix` (the operator's clock);
 *   • **attested** — the earliest final public witness over a checkpoint that
 *     includes the entry. Only this one stands, and it says *existed by*.
 *
 * The rule with teeth: an entry that claims a time earlier than the witness of
 * **the first head that held it** by more than the log's declared batch
 * allowance is reported as not supported — the planted backdated attestation.
 * Only the first head's witness can judge that: a later head's witness is an
 * upper bound and nothing more, so a proof against a later head leaves the
 * claimed time unjudged and says so. Whether a head is the entry's first is
 * read from the checkpoint's own `previous` head: the entry was not in it.
 * A claim later than any witness is impossible and reported always. A
 * backfilled entry is never faulted for an early claim: it says itself that
 * it came late — but only a claim from before the log began can be backfilled.
 * Given the log's start (the audit reads it from `log.json` and the first
 * head's witness), an entry marked backfilled that claims a later time loses
 * the mark and is judged as any other: otherwise the mark would be a way
 * around the rule for exactly the entries the log could have witnessed.
 */

import { claimedTimeOf, type LogEntry } from "./entries";
import type { WitnessVerdict } from "../witness/verdict";

/** How far a claimed time may run ahead of the witness before it is impossible: clock skew between an issuer and a witness. */
export const CLOCK_SKEW_SEC = 300;

export type TimeFault = "CLAIMED_BEFORE_WITNESS" | "CLAIMED_AFTER_WITNESS";

export interface TimeVerdict {
  /** `attested` — a final public witness stands behind it; `pending` — a witness was asked and has not answered; `unwitnessed` — only the log's own word. */
  readonly state: "attested" | "pending" | "unwitnessed";
  /** The earliest final witness time in the proof: the entry existed by then. */
  readonly attestedAtUnix: number | null;
  /** Which witness gave the attested time. */
  readonly by: string | null;
  readonly logClaimedAtUnix: number;
  readonly claimedAtUnix: number;
  /** Marked backfilled, and the mark holds: it claims a time from before the log began, or the log's start was not given. */
  readonly backfilled: boolean;
  /** Marked backfilled, but it claims a time after the log began — so it is judged as any other entry. */
  readonly backfillRefused: boolean;
  /** The proof's head is the first that held the entry, so its witness is the entry's first. Only then is an early claim judged. */
  readonly firstHead: boolean;
  readonly fault: TimeFault | null;
  /** The sentence a page shows. It names what each time is. */
  readonly text: string;
}

const iso = (unix: number): string => new Date(unix * 1000).toISOString().replace(".000Z", "Z");

export function timeVerdict(input: {
  readonly entry: LogEntry;
  readonly checkpointTimestampUnix: number;
  readonly witnesses: readonly WitnessVerdict[];
  readonly maxBatchDelaySec?: number;
  /** Default true: the caller vouches the head is the entry's first. A proof reads it from the checkpoint's `previous`. */
  readonly firstHead?: boolean;
  /** A time by which the log had certainly begun. A backfilled mark holds only for a claim before it. Unknown: the mark is taken as written. */
  readonly logStartedAtUnix?: number;
}): TimeVerdict {
  const claimed = claimedTimeOf(input.entry);
  const marked = input.entry.backfilled === true;
  const backfillRefused = marked && input.logStartedAtUnix !== undefined && claimed >= input.logStartedAtUnix;
  const backfilled = marked && !backfillRefused;
  const refusedText = backfillRefused ? ` — marked backfilled, but the log had begun by ${iso(input.logStartedAtUnix!)}, so it is judged as any other entry` : "";
  const firstHead = input.firstHead ?? true;
  const allowance = input.maxBatchDelaySec ?? 86_400;
  const finals = input.witnesses.filter((w) => w.state === "final" && w.digestOk && w.timeUnix !== null);
  const pending = input.witnesses.some((w) => w.state === "pending" && w.digestOk);
  if (finals.length === 0) {
    const state = pending ? "pending" : "unwitnessed";
    return {
      state,
      attestedAtUnix: null,
      by: null,
      logClaimedAtUnix: input.checkpointTimestampUnix,
      claimedAtUnix: claimed,
      backfilled,
      backfillRefused,
      firstHead,
      fault: null,
      text:
        `claimed ${iso(claimed)}; the log's own time ${iso(input.checkpointTimestampUnix)}; ` +
        (pending ? "a public witness was asked and has not answered yet — no attested time" : "no public witness — no attested time, only the log's word") +
        refusedText,
    };
  }
  const earliest = finals.reduce((a, b) => ((b.timeUnix as number) < (a.timeUnix as number) ? b : a));
  const attested = earliest.timeUnix as number;
  let fault: TimeFault | null = null;
  let text = `claimed ${iso(claimed)}; existed by ${iso(attested)}, attested by ${earliest.by}${refusedText}`;
  if (claimed > attested + CLOCK_SKEW_SEC) {
    fault = "CLAIMED_AFTER_WITNESS";
    text += " — the claimed time is after a witness stamped it, which cannot be: the attested time stands";
  } else if (backfilled) {
    text += " — logged after the log began, about something before it: attested when anchored, never backdated";
  } else if (!firstHead) {
    text += " — this proof is against a later head than the first that held the entry, so its witness is an upper bound and the claimed time is not judged here";
  } else if (claimed < attested - allowance) {
    fault = "CLAIMED_BEFORE_WITNESS";
    text += ` — the claimed time precedes the first witness by more than the log's allowance (${allowance} s): it is not supported; the attested time stands`;
  }
  return { state: "attested", attestedAtUnix: attested, by: earliest.by, logClaimedAtUnix: input.checkpointTimestampUnix, claimedAtUnix: claimed, backfilled, backfillRefused, firstHead, fault, text };
}
