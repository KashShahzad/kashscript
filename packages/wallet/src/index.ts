/**
 * @kashscript/wallet — the wallet component (PL-6; ECOSYSTEM d42 §2, d44,
 * d47 (a, e, f, g), d49). Apache-2.0.
 *
 * Keys first, no account: the first open makes a hardware root key and a
 * sealed vault on this device, and nothing else — no account, no server, no
 * install id. Everything the wallet does happens on the holder's device:
 *
 *   receive   the handoff — a place hands over a record (OID4VCI)
 *   hold      records as their issuers signed them, sealed, deleted at expiry for real
 *   present   one yes to an ask, never the data (OID4VP, SD-JWT VC)
 *   doors     a door's rule checked here first — a checklist, never a score —
 *             then a packet on the person's yes, a copy per viewer (d84(a))
 *   log       the holder's own record of what they showed, and to whom
 *   check     anyone's receipt, free, offline
 *   export    the whole wallet as one documented file; import it anywhere
 *   proof     the switch, per place, on this device only
 *   thankYous single notes, never summed; used only with whoever gave them
 *   sessions  the person's signature on each line of an encounter
 *   recovery  the interface only — helpers and succession arrive with PL-2
 *
 * Adapters: `@kashscript/wallet/expo` (the secure chip), `/web` (a browser —
 * weaker, and labelled so), `/headless` (practice runs for the simulation).
 */

import { copyWith } from "./copy";
import { checkArtifact, type CheckResult } from "./check";
import { WalletCore, type WalletConfig } from "./core";
import { Doors } from "./doors";
import { WalletError } from "./errors";
import { KeyRegistry, type RootReference } from "./keys";
import { PresentationLog } from "./log";
import type { WalletPlatform } from "./platform";
import { Present } from "./present";
import { Receive } from "./receive";
import { Records } from "./records";
import { Recovery } from "./recovery";
import { Relationships, type ProofChoice, type Relationship } from "./relationships";
import { Sessions } from "./session";
import { Signing } from "./sign";
import { ThankYous } from "./thank-you";
import { Transfer } from "./transfer";
import { TrustStore } from "./trust";
import { Vault } from "./vault";
import type { DsseEnvelope } from "@kashscript/attest/dsse";
import type { Ask } from "@kashscript/attest/exchange";
import type { FetchLike, StatusListReport, TrustListReport } from "@kashscript/attest/holder";

export const WALLET_VERSION = "0.1.0-alpha.5" as const;

export class Wallet {
  readonly receive: Receive;
  readonly present: Present;
  /** A door's rule, checked here first: a checklist, then a packet only on the person's yes (d84(a)). */
  readonly doors: Doors;
  readonly thankYous: ThankYous;
  readonly sessions: Sessions;
  /** The person's own signature on a record they author, with the key for one place. */
  readonly sign: Signing;
  readonly recovery: Recovery;
  private readonly transfer: Transfer;

  /** @internal — use {@link openWallet}. */
  constructor(private readonly core: WalletCore) {
    this.receive = new Receive(core);
    this.present = new Present(core);
    this.doors = new Doors(core);
    this.thankYous = new ThankYous(core);
    this.sessions = new Sessions(core);
    this.sign = new Signing(core);
    this.transfer = new Transfer(core);
    this.recovery = new Recovery(core, (text) => this.transfer.importAll(text));
  }

  /** What keeps the keys — the secure chip, a browser, or practice memory — in words to show. */
  root(): RootReference {
    return this.core.keys.root();
  }

  get unlocked(): boolean {
    return this.core.vault.unlocked;
  }

  /** One face, fingerprint or screen-lock prompt, then the records open until `lock`. */
  unlock(): Promise<void> {
    return this.core.vault.unlock();
  }

  /** Wipe the vault key from memory. Apps call this when they go to the background. */
  lock(): void {
    this.core.vault.lock();
  }

  readonly copy = (): WalletCore["copy"] => this.core.copy;

  /* ── the switch ──────────────────────────────────────────────────────── */

  readonly proof = {
    /** `unset` until the holder answers — never pre-ticked. */
    get: (counterparty: string): Promise<ProofChoice> => this.core.relationships.proof(counterparty),
    /** Stored on this device only. Never exported, backed up or sent. */
    set: (counterparty: string, choice: "on" | "off", label?: string): Promise<Relationship> => this.core.relationships.setProof(counterparty, choice, label),
  };

  readonly relationships = {
    list: (): Promise<readonly Relationship[]> => this.core.relationships.list(),
    /** The relay token for one relationship — PL-8's store-and-forward delivers to it without learning who holds it. */
    mailbox: async (counterparty: string): Promise<string | null> => (await this.core.relationships.find(counterparty))?.mailbox ?? null,
  };

  /* ── hold ────────────────────────────────────────────────────────────── */

  readonly records = {
    list: () => this.core.records.list(),
    get: (slot: string) => this.core.records.get(slot),
    /** The holder's own deletion. Crypto-shredded, like expiry. */
    remove: (slot: string): Promise<void> => this.core.records.remove(slot),
    /** Crypto-shred everything past its retention. Apps call it on open; export calls it first. */
    sweep: (): Promise<number> => this.core.records.sweep(),
  };

  readonly log = {
    list: () => this.core.log.list(),
  };

  /* ── trust, status and the ask library ───────────────────────────────── */

  readonly trust = {
    add: (envelope: DsseEnvelope): Promise<TrustListReport> => this.core.trust.addTrustList(envelope),
    reports: (): Promise<readonly TrustListReport[]> => this.core.trust.trustReports(),
  };

  readonly status = {
    carry: (envelope: DsseEnvelope): Promise<StatusListReport> => this.core.trust.carryStatusList(envelope),
    /** The one networked check, on the app's schedule — never at the moment of presenting. */
    prefetch: async (): Promise<readonly StatusListReport[]> => {
      const urls = new Set<string>();
      for (const e of await this.core.records.list()) if (e.manifest.status !== null) urls.add(e.manifest.status.statusListCredential);
      const fetchLike: FetchLike = async (url) => {
        const res = await this.core.getJson(url);
        return { ok: res.status >= 200 && res.status < 300, status: res.status, json: async () => res.json };
      };
      return this.core.trust.prefetchStatusLists([...urls], fetchLike);
    },
  };

  readonly asks = {
    /** Remember an ask from the public list, so a request can be matched against it. */
    remember: (ask: Ask): Promise<void> => this.core.trust.rememberAsk(ask),
  };

  /* ── check, export, import ───────────────────────────────────────────── */

  check(artifact: unknown): Promise<CheckResult> {
    return checkArtifact(this.core, artifact);
  }

  exportAll(opts: { readonly passphrase?: string } = {}) {
    return this.transfer.exportAll(opts);
  }

  importAll(text: string, opts: { readonly passphrase?: string } = {}) {
    return this.transfer.importAll(text, opts);
  }
}

/**
 * Open the wallet on this device — making the root and the vault on first run.
 * A new wallet comes back unlocked; an existing one comes back locked.
 */
export async function openWallet(platform: WalletPlatform, config: WalletConfig = {}): Promise<Wallet> {
  const copy = copyWith(config.copy);
  const vaultExists = await Vault.exists(platform.store);
  let root = await platform.roots.open();
  if (root === null) {
    if (vaultExists) throw new WalletError("ROOT_LOST", "a vault exists but its root is gone");
    root = await platform.roots.create();
  }
  const vault = vaultExists
    ? await Vault.open(platform.store, root, platform.random, copy.unlockPrompt)
    : await Vault.create(platform.store, root, platform.random, copy.unlockPrompt);
  const pinned = config.pinnedPublishers ?? [];
  const keys = new KeyRegistry(vault, root, platform.random, platform.now, platform.signers ?? null, copy.signPrompt);
  const trust = new TrustStore(vault, pinned, platform.now);
  const core = new WalletCore(
    vault,
    root,
    keys,
    new Relationships(vault, keys, platform.random, platform.now),
    new Records(vault, trust, platform.now),
    trust,
    new PresentationLog(vault),
    copy,
    platform.random,
    platform.now,
    Math.max(1, Math.min(config.batchSize ?? 5, 20)),
    pinned,
    platform.transport,
  );
  return new Wallet(core);
}

export { WalletError, ERROR_MESSAGES, isWalletError, type WalletErrorCode } from "./errors";
export { DEFAULT_COPY, copyWith, fill, type Copy } from "./copy";
export type { WalletConfig } from "./core";
export type { BlobStore, Clock, HardwareRoot, HardwareSigners, HttpRequest, HttpResponse, Random, RootInfo, RootProvider, RootStrength, RootWhere, Transport, WalletPlatform } from "./platform";
export { systemClock, systemRandom } from "./platform";
export { fetchTransport } from "./transport";
export type { ProofChoice, Relationship } from "./relationships";
export type { HeldEntry, RecordLocal } from "./records";
export type { CheckResult, CheckState } from "./check";
export type { AskView, NeedView, PresentResult, PresentationRequest } from "./present";
export type { DoorView, DoorSendResult } from "./doors";
export type { OfferView, PendingRecords, ReceiveResult, CredentialOffer } from "./receive";
export type { ThankYouNote, RedeemRequest } from "./thank-you";
export type { CosignResult, JoinResult } from "./session";
export { HOLDER_SIGNABLE_PAYLOAD_TYPES, MAX_SIGNED_PAYLOAD_BYTES, type SignDsseOptions, type SignDsseResult } from "./sign";
export type { FinishResult, Helper, HelperEnrolment, HelperInvite, HelperView, Quorum, RecoveryApproval, RecoveryRequest, RecoveryStatus } from "./recovery";
export { HELPER_POOL_SIZE, recoveryCode } from "./recovery";
export type { ExportResult, ImportResult } from "./transfer";
export type { KeyEntry, RootReference, WalletEventSigner, WalletSigner } from "./keys";
export { VAULT_FORMAT } from "./vault";
