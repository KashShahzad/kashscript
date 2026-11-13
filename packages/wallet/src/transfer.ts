/**
 * Export and import — the holder contract's bundle, `kashscript-holder-export/1`
 * (§2). A wallet you cannot leave is custody under another name (d42 §2, rule 2).
 *
 * Export: sweeps expired records first, writes the byte-stable file, and has
 * attest verify it — offline — before handing it over. It carries every
 * record with its manifest, the lists the wallet carries, and the holder's own
 * presentation log. Keys go in only as the encrypted backup, and only when the
 * holder gives a passphrase. The switch is in no export: on a new device the
 * holder is asked again.
 *
 * Import: attest verifies the file offline first; records past their
 * retention are dropped (an export never resurrects a deleted record); each
 * record is sealed afresh under a new key; keys come back only with the
 * passphrase; which copy was shown to which verifier is rebuilt from the log,
 * so a copy is never shown to a second verifier after a move.
 */

import {
  isHolderExport,
  serializeHolderExport,
  verifyHolderExport,
  HOLDER_EXPORT_FORMAT,
  type HolderExport,
  type HolderExportReport,
} from "@kashscript/attest/holder";
import { credentialCopySha256, validatePresentationLog, type PresentationLogEntry } from "@kashscript/attest/exchange";
import { decryptKeyBackup, encryptKeyBackup } from "./crypto/jwe";
import type { WalletCore } from "./core";
import { WalletError } from "./errors";
import { probeArtifact } from "./records";
import { exportedHelperSets, keepClaims, storedClaims } from "./recovery";

export interface ExportResult {
  /** The file's exact bytes: RFC 8785, records sorted by id, no trailing newline. */
  readonly text: string;
  readonly report: HolderExportReport;
  readonly records: number;
  readonly keysIncluded: boolean;
  /** Keys that live in the secure chip and so are in no file, ever — after a loss, helpers bring them back (PL-2). */
  readonly keysInChip: number;
}

export interface ImportResult {
  readonly records: number;
  readonly dropped: number;
  readonly keysRestored: number;
  /** True when the file carried a key backup that was not opened (no passphrase given). */
  readonly keysLeftLocked: boolean;
  readonly report: HolderExportReport;
}

export class Transfer {
  constructor(private readonly core: WalletCore) {}

  async exportAll(opts: { readonly passphrase?: string } = {}): Promise<ExportResult> {
    await this.core.records.sweep();
    const now = this.core.now();
    const ctx = await this.core.trust.context();
    const records = [];
    for (const e of await this.core.records.list()) {
      // Listing is re-read now: a list that has lapsed no longer vouches for anyone.
      const probe = await probeArtifact(e.artifact, ctx);
      const listed = probe.listing.evidence === "pinned-list";
      const kept = e.manifest.keptUnlistedAtUnix ?? e.manifest.receivedAtUnix;
      records.push({
        manifest: {
          ...e.manifest,
          listing: listed ? ("listed" as const) : ("unlisted" as const),
          keptUnlistedAtUnix: listed || e.manifest.type.attestation === "device-asserted" ? null : kept,
        },
        artifact: e.artifact,
      });
    }
    const log = await this.core.log.list();
    const helperSets = await exportedHelperSets(this.core);
    const file: HolderExport = {
      formatVersion: HOLDER_EXPORT_FORMAT,
      exportedAtUnix: now,
      records,
      keySuccession: await storedClaims(this.core),
      trustLists: [...(await this.core.trust.trustEnvelopes())],
      statusLists: [...(await this.core.trust.statusEnvelopes())],
      revocations: [...(await this.core.trust.revocations())],
      heldKeys: [...(await this.core.trust.heldKeys())],
      encryptedKeyBackup:
        opts.passphrase === undefined ? null : await encryptKeyBackup({ keys: await this.core.keys.backupEntries() }, opts.passphrase, this.core.random),
      ...(log.length > 0 ? { presentationLog: log } : {}),
      // v1.3: each current key's helper set, with where it is used — what a new phone recovers from.
      ...(helperSets.length > 0 ? { recoveryHelpers: helperSets } : {}),
    };
    const text = serializeHolderExport(file);
    const report = await verifyHolderExport(JSON.parse(text), { pinnedPublishers: this.core.pinnedPublishers, nowSec: now, rawText: text });
    if (!report.ok || report.canonical !== true) throw new WalletError("EXPORT_INVALID", report.reasons.join(", "));
    return { text, report, records: records.length, keysIncluded: file.encryptedKeyBackup !== null, keysInChip: await this.core.keys.hardwareKeyCount() };
  }

  async importAll(text: string, opts: { readonly passphrase?: string } = {}): Promise<ImportResult> {
    let value: unknown;
    try {
      value = JSON.parse(text);
    } catch {
      throw new WalletError("IMPORT_INVALID", "not JSON");
    }
    if (!isHolderExport(value)) throw new WalletError("IMPORT_INVALID", "not a holder export");
    const now = this.core.now();
    const report = await verifyHolderExport(value, { pinnedPublishers: this.core.pinnedPublishers, nowSec: now, rawText: text });
    if (!report.ok) throw new WalletError("IMPORT_INVALID", report.reasons.join(", "));

    // Keys first (only with the passphrase), so records can be bound to them.
    let keysRestored = 0;
    if (value.encryptedKeyBackup !== null && opts.passphrase !== undefined) {
      const plain = await decryptKeyBackup(value.encryptedKeyBackup, opts.passphrase);
      keysRestored = await this.core.keys.restoreAll(plain.keys);
    }
    for (const env of value.trustLists) await this.core.trust.addTrustList(env);
    for (const k of value.heldKeys) await this.core.trust.addHeldKey(k);
    for (const env of value.statusLists) await this.core.trust.carryStatusList(env);
    for (const r of value.revocations) await this.core.trust.addRevocation(r);
    await keepClaims(this.core, value.keySuccession);

    const log = value.presentationLog ?? [];
    if (!validatePresentationLog(log).ok) throw new WalletError("IMPORT_INVALID", "the presentation log is invalid");
    const shownTo = new Map<string, string>();
    for (const entry of log) {
      if (entry.kind === "presentation") for (const c of entry.credentials) if (!shownTo.has(c.copySha256)) shownTo.set(c.copySha256, entry.verifier);
    }

    let records = 0;
    let dropped = 0;
    for (let i = 0; i < value.records.length; i++) {
      const rec = value.records[i]!;
      if (report.records[i]?.retention.pastNow) {
        dropped++;
        continue;
      }
      const copyHash = rec.artifact.kind === "sd-jwt" && typeof rec.artifact.value === "string" ? await credentialCopySha256(rec.artifact.value) : null;
      const boundKey = rec.manifest.relationship !== null && (await this.core.keys.find(rec.manifest.relationship)) !== null ? rec.manifest.relationship : null;
      await this.core.records.hold(rec, {
        counterparty: null,
        boundKey,
        copyGroup: null,
        assignedVerifier: copyHash === null ? null : shownTo.get(copyHash) ?? null,
      });
      records++;
    }
    await this.mergeLog(log);
    return { records, dropped, keysRestored, keysLeftLocked: value.encryptedKeyBackup !== null && opts.passphrase === undefined, report };
  }

  private async mergeLog(incoming: readonly PresentationLogEntry[]): Promise<void> {
    const have = new Set((await this.core.log.list()).map((e) => JSON.stringify(e)));
    const fresh = incoming.filter((e) => !have.has(JSON.stringify(e)));
    if (fresh.length > 0) await this.core.log.append(...fresh);
  }
}
