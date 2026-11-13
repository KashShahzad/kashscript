/**
 * `kash trust sign <file>` — sign a trust list or a status list with the publisher key.
 *
 * The founder signs, with the publisher key only they hold (d62(d)5): trust and
 * status lists are signed muffler records any host may mirror, and the wallet
 * pins the publisher's DID out of band. This writes the signed envelope — the
 * wallet's own list format, via attest's `signTrustList` / `signStatusList` —
 * to standard output (and to `--out`, if asked). It uploads nothing; publishing
 * the file is a separate act.
 *
 * The publisher is its own role: the default key is `publisher`, never the
 * station's. Standard output carries only the signed JSON, so it pipes; every
 * note goes to standard error.
 *
 * Before it prints, it checks its own work with attest's verifiers and refuses
 * to print a list that would not verify.
 */

import {
  AttestError,
  STATUS_LIST_FORMAT,
  TRUST_LIST_FORMAT,
  makeKeyResolver,
  signStatusList,
  signTrustList,
  verifyStatusList,
  verifyTrustList,
  type DsseEnvelope,
  type StatusListPayload,
  type TrustListPayload,
} from "@kashscript/attest";

import { KashCliError } from "../errors";
import { loadKey } from "../keystore/store";
import { readJsonFile, writeOutput } from "../utils/files";

export interface TrustSignOptions {
  readonly key?: string;
  readonly keystore?: string;
  readonly out?: string;
}

function note(line: string): void {
  process.stderr.write(`${line}\n`);
}

const iso = (unix: number | null): string => (unix === null ? "never" : new Date(unix * 1000).toISOString().replace(".000Z", "Z"));

export async function runTrustSign(file: string, opts: TrustSignOptions = {}): Promise<void> {
  const publisher = await loadKey(opts.key ?? "publisher", opts.keystore);
  const raw = readJsonFile(file, "the list to sign");
  const payload = raw as Record<string, unknown>;

  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    throw new KashCliError("The list to sign must be a JSON object.", "INVALID_INPUT");
  }
  if (typeof payload["payloadType"] === "string" && Array.isArray(payload["signatures"])) {
    throw new KashCliError("That file is already a signed envelope. Give kash the unsigned list (its payload) to sign.", "INVALID_INPUT");
  }

  const signer = { keyid: publisher.did, privateKey: publisher.privateKey, publicKey: publisher.publicKey };
  let envelope: DsseEnvelope;
  let summary: string;

  try {
    if (payload["format"] === TRUST_LIST_FORMAT) {
      const named = payload["publisher"];
      if (named !== undefined && named !== publisher.did) {
        throw new KashCliError(`The list names the publisher ${String(named)}, but this key is ${publisher.did}. Nothing was signed.`, "KEY_INVALID");
      }
      const list = { ...payload, publisher: publisher.did } as unknown as TrustListPayload;
      envelope = await signTrustList(list, signer);
      const report = await verifyTrustList(envelope, { pinnedPublishers: [publisher.did] });
      if (!report.ok) throw new KashCliError(`The signed list does not verify (${report.reason}). Nothing was printed.`, "RECORD_INVALID");
      summary = `Trust list ${report.listId} v${report.version}: ${report.issuers.length} issuer(s), valid until ${iso(report.validUntilUnix)}.`;
      if (!report.current) note("! This list is outside its validity window now, so a wallet would treat it as listing nobody.");
    } else if (payload["format"] === STATUS_LIST_FORMAT) {
      const named = payload["issuer"];
      if (named !== undefined && named !== publisher.did) {
        throw new KashCliError(`The list names the issuer ${String(named)}, but this key is ${publisher.did}. Nothing was signed.`, "KEY_INVALID");
      }
      const list = { ...payload, issuer: publisher.did } as unknown as StatusListPayload;
      envelope = await signStatusList(list, signer);
      const report = await verifyStatusList(envelope, { resolveKey: makeKeyResolver(new Map(), new Map()) });
      if (!report.ok) throw new KashCliError(`The signed list does not verify (${report.reason}). Nothing was printed.`, "RECORD_INVALID");
      summary = `Status list ${report.id} (${report.statusPurpose}): ${report.entries} entries, as of ${iso(report.issuedAtUnix)}.`;
    } else {
      throw new KashCliError(
        `Not a list kash signs: "format" is ${JSON.stringify(payload["format"])}; expected ${TRUST_LIST_FORMAT} or ${STATUS_LIST_FORMAT}.`,
        "INVALID_INPUT",
      );
    }
  } catch (err) {
    if (err instanceof AttestError) throw new KashCliError(err.message, "RECORD_INVALID", err);
    throw err;
  }

  const text = JSON.stringify(envelope, null, 2) + "\n";
  if (opts.out !== undefined) {
    const written = writeOutput(opts.out, text);
    note(`✓ Wrote ${written}`);
  }
  process.stdout.write(text);

  note(`✓ ${summary}`);
  note(`  signed by the publisher ${publisher.did}`);
  note("  A wallet trusts it only if the app pins that publisher DID out of band — a list from any other publisher lists nobody.");
  note("  Nothing was uploaded. Publishing the file is yours to do, anywhere that can mirror it.");
}
