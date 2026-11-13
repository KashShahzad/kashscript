/**
 * What the wallet trusts, and what it carries so checking stays offline.
 *
 * - **Trust lists** (holder contract §3; d47(e)). Only a list whose publisher
 *   was pinned out of band makes a record "listed" — the app ships its
 *   publisher's identifier; this package ships none. It is a policy, not the
 *   format: an unlisted issuer's record may still be kept, by the holder's
 *   explicit choice, and it shows as unlisted.
 * - **Status lists** (§4) are carried. Fetching them is an explicit call the
 *   app schedules, never a side effect of presenting, and it is the only time
 *   checking touches the network.
 * - **The ask library**: the wallet's copy of the public list of requests, so
 *   it can tell whether a request matches what was published (rule 5).
 */

import { canonicalize } from "@kashscript/identity-core";
import type { DsseEnvelope } from "@kashscript/attest/dsse";
import {
  fetchStatusLists,
  makeKeyResolver,
  trustListKeyMap,
  verifyStatusList,
  verifyTrustList,
  currentTrustLists,
  type FetchLike,
  type HeldKey,
  type HeldRecordContext,
  type KeyResolver,
  type StatusListReport,
  type TrustListReport,
  typedKeyOf,
} from "@kashscript/attest/holder";
import { askSha256, validateAsk, type Ask } from "@kashscript/attest/exchange";
import type { SignedKashEvent } from "@kashscript/identity-core";
import { WalletError } from "./errors";
import type { Clock } from "./platform";
import { PREFIX, type Vault } from "./vault";

interface AskEntry {
  readonly key: string;
  readonly version: number;
  readonly sha256: string;
}

export type LibraryState = "in-library" | "not-in-library" | "mismatch";

export class TrustStore {
  constructor(
    private readonly vault: Vault,
    private readonly pinnedPublishers: readonly string[],
    private readonly now: Clock,
  ) {}

  /* ── trust lists ─────────────────────────────────────────────────────── */

  async addTrustList(envelope: DsseEnvelope): Promise<TrustListReport> {
    const report = await verifyTrustList(envelope, { pinnedPublishers: this.pinnedPublishers, nowSec: this.now() });
    if (!report.ok) return report;
    // Keep the highest version of each list. A list is its publisher's own: another publisher's list with the same id is a
    // different list, so a higher number from a publisher nobody pinned can never push out the pinned one (it would
    // otherwise be enough to hand the wallet a file — a restored backup, say — to make every sender read unlisted).
    for (const { name, value } of await this.vault.all<DsseEnvelope>(PREFIX.trustList)) {
      const r = await verifyTrustList(value, { pinnedPublishers: this.pinnedPublishers, nowSec: this.now() });
      if (r.publisher !== report.publisher || r.listId !== report.listId) continue;
      if (r.pinned && !report.pinned) return r;
      if ((r.version ?? -1) >= (report.version ?? -1)) return r;
      await this.vault.remove(name);
    }
    await this.vault.put(PREFIX.trustList + (await this.vault.newSlot()), envelope);
    return report;
  }

  async trustEnvelopes(): Promise<readonly DsseEnvelope[]> {
    return (await this.vault.all<DsseEnvelope>(PREFIX.trustList)).map((e) => e.value);
  }

  async trustReports(): Promise<readonly TrustListReport[]> {
    const out: TrustListReport[] = [];
    for (const env of await this.trustEnvelopes()) out.push(await verifyTrustList(env, { pinnedPublishers: this.pinnedPublishers, nowSec: this.now() }));
    return out;
  }

  /** The lists that can list anyone right now: pinned, current, highest version. */
  async currentLists(): Promise<readonly TrustListReport[]> {
    return currentTrustLists((await this.trustReports()).filter((r) => r.pinned));
  }

  /* ── keys a record may be signed with ────────────────────────────────── */

  async addHeldKey(key: HeldKey): Promise<void> {
    if (typedKeyOf(key) === null) throw new WalletError("IMPORT_INVALID", `held key ${key.keyid} is malformed`);
    if ((await this.heldKeys()).some((k) => k.keyid === key.keyid)) return;
    await this.vault.put(PREFIX.heldKey + (await this.vault.newSlot()), key);
  }

  async heldKeys(): Promise<readonly HeldKey[]> {
    return (await this.vault.all<HeldKey>(PREFIX.heldKey)).map((e) => e.value);
  }

  async resolver(): Promise<KeyResolver> {
    // Ed25519 or ES256 — each held key keeps its type, so it verifies only its own algorithm.
    const held = new Map<string, NonNullable<ReturnType<typeof typedKeyOf>>>();
    for (const k of await this.heldKeys()) {
      const key = typedKeyOf(k);
      if (key !== null) held.set(k.keyid, key);
    }
    return makeKeyResolver(trustListKeyMap(await this.trustReports()), held);
  }

  /* ── status lists, carried ───────────────────────────────────────────── */

  async carryStatusList(envelope: DsseEnvelope): Promise<StatusListReport> {
    const report = await verifyStatusList(envelope, { resolveKey: await this.resolver(), nowSec: this.now(), source: "carried" });
    if (!report.ok) return report;
    for (const { name, value } of await this.vault.all<DsseEnvelope>(PREFIX.statusList)) {
      const r = await verifyStatusList(value, { resolveKey: await this.resolver(), nowSec: this.now(), source: "carried" });
      if (r.id === report.id && r.statusPurpose === report.statusPurpose) {
        if ((r.issuedAtUnix ?? 0) >= (report.issuedAtUnix ?? 0)) return r;
        await this.vault.remove(name);
      }
    }
    await this.vault.put(PREFIX.statusList + (await this.vault.newSlot()), envelope);
    return report;
  }

  async statusEnvelopes(): Promise<readonly DsseEnvelope[]> {
    return (await this.vault.all<DsseEnvelope>(PREFIX.statusList)).map((e) => e.value);
  }

  async statusReports(): Promise<readonly StatusListReport[]> {
    const resolveKey = await this.resolver();
    const out: StatusListReport[] = [];
    for (const env of await this.statusEnvelopes()) out.push(await verifyStatusList(env, { resolveKey, nowSec: this.now(), source: "carried" }));
    return out;
  }

  /**
   * Fetch the lists these URLs name and carry the good ones. The one networked
   * check, called by the app on its own schedule — never at the moment of
   * presenting. `fetchLike` carries no identifier: a list is shared by many
   * records, so its host learns only that someone checks that list.
   */
  async prefetchStatusLists(urls: readonly string[], fetchLike: FetchLike): Promise<readonly StatusListReport[]> {
    const out: StatusListReport[] = [];
    for (const f of await fetchStatusLists(urls, fetchLike)) {
      if (f.envelope !== null) out.push(await this.carryStatusList(f.envelope));
    }
    return out;
  }

  /* ── presented revocations ───────────────────────────────────────────── */

  async addRevocation(event: SignedKashEvent): Promise<void> {
    const text = canonicalize(event);
    if ((await this.revocations()).some((r) => canonicalize(r) === text)) return;
    await this.vault.put(PREFIX.revocation + (await this.vault.newSlot()), event);
  }

  async revocations(): Promise<readonly SignedKashEvent[]> {
    return (await this.vault.all<SignedKashEvent>(PREFIX.revocation)).map((e) => e.value);
  }

  /* ── the verification context, for attest ────────────────────────────── */

  async context(exportedAtUnix: number | null = null): Promise<HeldRecordContext> {
    return {
      resolveKey: await this.resolver(),
      trustLists: await this.trustReports(),
      statusLists: await this.statusReports(),
      revocations: await this.revocations(),
      nowSec: this.now(),
      exportedAtUnix,
    };
  }

  /* ── the ask library ─────────────────────────────────────────────────── */

  async rememberAsk(ask: Ask): Promise<void> {
    if (!validateAsk(ask).ok) throw new WalletError("ASK_REFUSED", "the ask breaks the rules");
    const entry: AskEntry = { key: ask.key, version: ask.version, sha256: await askSha256(ask) };
    for (const { name, value } of await this.vault.all<AskEntry>(PREFIX.ask)) {
      if (value.key === entry.key && value.version === entry.version) await this.vault.remove(name);
    }
    await this.vault.put(PREFIX.ask + (await this.vault.newSlot()), entry);
  }

  async libraryState(ask: Ask, sha256: string): Promise<LibraryState> {
    const found = (await this.vault.all<AskEntry>(PREFIX.ask)).map((e) => e.value).find((e) => e.key === ask.key && e.version === ask.version);
    if (found === undefined) return "not-in-library";
    return found.sha256 === sha256 ? "in-library" : "mismatch";
  }
}
