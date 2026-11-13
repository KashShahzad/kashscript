/**
 * The checker's plain layer — design language §5.6 and law 9, "a tick is never alone".
 *
 * Every verdict the CLI prints is followed by three plain statements, so a stranger with a file can read the result
 * without reading the report: who signed, what was checked, and what this does not prove. They are CLI text only —
 * derived from the reports the verifiers already return, never a new field on one, and never a different pass or
 * fail. They go immediately before the `RESULT:` line, so every line the CLI printed before still prints, byte for
 * byte, and `RESULT:` stays last.
 *
 * Wording rules, from the tests and consumers that read this output:
 *  - never the word "trusted" — a record is "listed" only by a list the reader pinned (holder-cli.test.ts);
 *  - none of "reason", "fault" or "FAIL" — Indorania's simulation filters stdout on them;
 *  - a `did:kash` is a key, not a person, and the layer says so wherever a signer is named.
 */
import type { AuditBundleVerifyReport } from "../bundle";
import type { DuedaleReportVerifyReport } from "../compat/duedale-report";
import type { IndusVerifyResult } from "../compat/indus-token";
import type { CountersignVerifyReport } from "../countersign";
import type { HolderExportReport, StatusListReport, TrustListReport } from "../holder";
import type { SdJwtReport } from "../sd-jwt";
import type { PredicatePresentationReport, SessionReceiptReport, ThankYouReport } from "../exchange";
import type { CohortRecordReport } from "../profiles";

/** The three statements. `signed` is who put their name to it, in the file's own words (keys, not people). */
export interface PlainLayer {
  readonly signed: readonly string[];
  readonly checked: string;
  readonly notProven: string;
}

const PAD = 19;
const line = (label: string, value: string): string => `  ${label.padEnd(PAD)}: ${value}`;
const uniq = (xs: readonly (string | null | undefined)[]): string[] => [...new Set(xs.filter((x): x is string => typeof x === "string" && x.length > 0))];

/**
 * The three lines for a result. When the check did not pass, "who signed" becomes "claims signed by": the names are
 * what the file says, not something it showed.
 */
export function plainLines(layer: PlainLayer, ok: boolean): string[] {
  const who = layer.signed.length === 0 ? "nobody — the file carries no signature" : layer.signed.join(", ");
  return [
    line(ok ? "who signed" : "claims signed by", who),
    line("what was checked", layer.checked),
    line("does not prove", layer.notProven),
  ];
}

const KEY_NOT_PERSON = "who holds a key, or whether what it signed is true";

export function plainCountersign(r: CountersignVerifyReport): PlainLayer {
  return {
    signed: uniq([r.requesterDid, ...r.acceptances.map((a) => a.countersignerDid)]),
    checked: "the request signature; each acceptance — its signature, its binding to the request, its time window; two keys over the same bytes",
    notProven: `${KEY_NOT_PERSON}; that nobody has withdrawn (checked offline); the signing times, which are the signers' own claims`,
  };
}

export function plainCohort(r: CohortRecordReport): PlainLayer {
  return {
    signed: r.ok
      ? uniq([r.teacherOrgDid, r.stationDid])
      : uniq([r.countersign.requesterDid, ...r.countersign.acceptances.map((a) => a.countersignerDid)]),
    checked: "both organisations' signatures over the same bytes, each bound to the request and its window; that the record follows the cohort profile — finished, under a syllabus named by version and hash, with no grade, score, rank or payer; its expiry",
    notProven: `how well anyone learned — there is no grade, score or rank, and no skill level; ${KEY_NOT_PERSON}; that these keys are that teacher's organisation and that station — a charter, or a trust list you pinned, says so; who paid; that nobody has withdrawn (checked offline)`,
  };
}

export function plainHolderExport(r: HolderExportReport): PlainLayer {
  return {
    signed: uniq(r.records.map((rec) => rec.issuer)),
    checked: "each record's signature and manifest; every trust-list and status-list signature; key succession; whether the file's bytes are canonical",
    notProven: "that a record is true; that an issuer is who it says unless a list you pinned names it; revocation unless a status list came with it (--status-list, or --check-status)",
  };
}

export function plainPredicate(r: PredicatePresentationReport): PlainLayer {
  const holder = r.sdJwt.keyBinding.present ? `the holder's relationship key${r.sdJwt.holder ? ` (${r.sdJwt.holder})` : ""}` : null;
  return {
    signed: uniq([r.issuer, holder]),
    checked: "the issuer's signature; the holder's binding, audience and nonce where given; the rule version and window; status where a list was presented",
    notProven: "the records behind the answer (only hashes are disclosed); that the rule is a good one; who the holder is",
  };
}

export function plainThankYou(r: ThankYouReport, presented: boolean): PlainLayer {
  return {
    signed: uniq([r.issuer]),
    checked: presented
      ? "the issuer's signature; the holder's binding; that it went to its own issuer; the nonce where given; status"
      : "the issuer's signature; status where a list was presented",
    notProven: "that the promise will be kept; that the giver was free to give it — it is a promise, not a balance",
  };
}

export function plainSdJwt(r: SdJwtReport): PlainLayer {
  return {
    signed: uniq([r.issuer]),
    checked: "the issuer's signature; the holder's binding where one is present",
    notProven: "what the disclosed claims mean; who holds it, unless a holder binding was presented",
  };
}

export function plainSession(r: SessionReceiptReport): PlainLayer {
  // The parties are named by key; a line's `signers` are only the roles that signed it, so they stand in when no parties are named.
  const signers = r.parties !== null ? uniq([r.parties.establishment, r.parties.person]) : uniq(r.events.flatMap((e) => e.signers));
  return {
    signed: signers,
    checked: "both parties' signatures on every line; the total against its hashed line items; the anchor where there is one"
      + (r.anchor?.inclusion !== undefined ? ", and its place in its batch by its own path to the root the anchor names" : ""),
    notProven: (r.state === "complete"
      ? "what was bought (the line items are hashes); that the goods or service arrived"
      : "anything yet — it is pending, so it is not proof; and not what was bought, or that it arrived")
      + (r.anchor === null
        ? ""
        : r.anchor.backend === "none"
          ? "; that any public log saw the anchor — it is recorded only"
          : "; that a public log holds the anchor (rekor-cli, ots verify)"),
  };
}

export function plainAsk(): PlainLayer {
  return {
    signed: [],
    checked: "the eight rules for an ask, and the forbidden needs",
    notProven: "who is asking; that the need is lawful where you are; that answering is wise",
  };
}

export function plainBundle(r: AuditBundleVerifyReport, keyGiven: boolean): PlainLayer {
  return {
    signed: uniq([...r.dsseVerifiedKeyids]),
    checked: "the envelope signature; the required signer; the hash chain row by row; the anchor where there is one",
    notProven: `${KEY_NOT_PERSON}; that the actions were right — only that the log was not changed after it was signed; public-log inclusion (rekor-cli, ots verify)${keyGiven ? "" : "; the signer's key came from the file itself, so confirm it out of band"}`,
  };
}

export function plainReport(r: DuedaleReportVerifyReport, keyGiven: boolean): PlainLayer {
  return {
    signed: [`operator key ${r.operatorPublicKeyHex.slice(0, 16)}…`],
    checked: "the envelope signature; the hash chain of transitions",
    notProven: `who the operator is; that the figures are right — only that they were not changed after signing${keyGiven ? "" : "; the key came from the file itself, so confirm it out of band"}`,
  };
}

export function plainIndus(r: IndusVerifyResult): PlainLayer {
  return {
    signed: uniq([r.kid]),
    checked: `the signature against the key you gave; the time window${r.certIdOk !== null ? "; the certificate id derivation" : ""}`,
    notProven: "who holds the token; that the key belongs to the issuer it names — you supplied the key, so that is your check",
  };
}

export function plainTrustList(r: TrustListReport): PlainLayer {
  return {
    signed: uniq([r.publisher]),
    checked: "the list's signature; its validity window; whether you pinned its publisher",
    notProven: "that the issuers it lists deserve to be; that no newer list exists",
  };
}

export function plainStatusList(r: StatusListReport): PlainLayer {
  return {
    signed: uniq([r.issuer]),
    checked: "the list's signature, against the key inside its issuer's did:kash",
    notProven: "that a record's status is current — a newer list may exist; who the issuer is",
  };
}

/** The tamper path stops before any report exists, so what it can say is what the check was. */
export function plainTamper(): PlainLayer {
  return {
    signed: ["unknown — the check stopped at the first break"],
    checked: "the envelope signature and the hash chain, in order, until the first break",
    notProven: "who changed it, or when; only that it is no longer what was signed",
  };
}
