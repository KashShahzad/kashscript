/**
 * Relationships, and the proof switch (d49(a)).
 *
 * A relationship is the holder and one place: its own key (the only name that
 * place knows the holder by), its own mailbox token for a relay, and the
 * holder's choice about keeping records with it. Nothing here is shared
 * between relationships, so linking two of them is something the holder does,
 * never something done to them (d41).
 *
 * **The switch** is asked once per relationship, remembered on this device
 * only, and never pre-ticked: it starts `unset`. It is in no export, no backup
 * and no request. Off means the wallet sends nothing — no redemption, no
 * signature — and a decline leaves no trace, because there is nothing to leave.
 */

import { bytesToBase64Url, bytesToHex } from "./crypto/bytes";
import type { KeyRegistry } from "./keys";
import type { Clock, Random } from "./platform";
import { PREFIX, type Vault } from "./vault";

export type ProofChoice = "unset" | "on" | "off";

export interface Relationship {
  readonly slot: string;
  /** Local only; never sent anywhere. */
  readonly id: string;
  /** The place's own stable identifier — an https origin, or its identifier. */
  readonly counterparty: string;
  readonly label: string;
  /** The holder's key with this place, made on first use. */
  readonly keyId: string | null;
  /** The place's session identifier with the holder, once learned. */
  readonly theirDid: string | null;
  /** A random token for this relationship alone — a relay delivers to it without knowing who holds it. */
  readonly mailbox: string;
  readonly proof: ProofChoice;
  readonly createdAtUnix: number;
}

/** An https URL's origin, so every link from one place names one relationship. */
export function counterpartyOf(value: string): string {
  try {
    const u = new URL(value);
    if (u.protocol === "https:") return u.origin;
  } catch {
    /* not a URL — an identifier */
  }
  return value;
}

export class Relationships {
  /** Called once with each new relationship key — recovery names its helpers then (PL-2). */
  private onNewKey: ((r: Relationship & { keyId: string }) => Promise<void>) | null = null;

  constructor(
    private readonly vault: Vault,
    private readonly keys: KeyRegistry,
    private readonly random: Random,
    private readonly now: Clock,
  ) {}

  /** @internal — recovery registers here, so every place's key is covered as it is made. */
  whenKeyMade(fn: (r: Relationship & { keyId: string }) => Promise<void>): void {
    this.onNewKey = fn;
  }

  async list(): Promise<readonly Relationship[]> {
    return (await this.vault.all<Relationship>(PREFIX.relationship)).map((r) => r.value);
  }

  async find(counterparty: string): Promise<Relationship | null> {
    const c = counterpartyOf(counterparty);
    return (await this.list()).find((r) => r.counterparty === c) ?? null;
  }

  async findByKey(keyId: string): Promise<Relationship | null> {
    return (await this.list()).find((r) => r.keyId === keyId) ?? null;
  }

  private async save(r: Relationship): Promise<Relationship> {
    await this.vault.put(PREFIX.relationship + r.slot, r);
    return r;
  }

  /** The relationship, made (switch unset, no key yet) if this is the first contact. */
  async ensure(counterparty: string, label?: string): Promise<Relationship> {
    const found = await this.find(counterparty);
    if (found !== null) return found;
    const c = counterpartyOf(counterparty);
    return this.save({
      slot: await this.vault.newSlot(),
      id: bytesToHex(await this.random(16)),
      counterparty: c,
      label: label ?? c,
      keyId: null,
      theirDid: null,
      mailbox: bytesToBase64Url(await this.random(32)),
      proof: "unset",
      createdAtUnix: this.now(),
    });
  }

  /** The holder's key with this place, made the first time it is needed. */
  async ensureKey(r: Relationship): Promise<Relationship & { keyId: string }> {
    if (r.keyId !== null) return r as Relationship & { keyId: string };
    const key = await this.keys.create("relationship");
    const saved = (await this.save({ ...r, keyId: key.keyId })) as Relationship & { keyId: string };
    if (this.onNewKey !== null) await this.onNewKey(saved);
    return saved;
  }

  /** A recovered place moves to its successor key (PL-2). The switch is not carried: it stays as it is on this device. */
  async adoptKey(r: Relationship, keyId: string): Promise<Relationship & { keyId: string }> {
    return (await this.save({ ...r, keyId })) as Relationship & { keyId: string };
  }

  async proof(counterparty: string): Promise<ProofChoice> {
    return (await this.find(counterparty))?.proof ?? "unset";
  }

  /** The holder's answer to "keep a record of this?" — stored on this device and nowhere else. */
  async setProof(counterparty: string, choice: "on" | "off", label?: string): Promise<Relationship> {
    const r = await this.ensure(counterparty, label);
    return this.save({ ...r, proof: choice, ...(label !== undefined ? { label } : {}) });
  }

  async learnTheirDid(r: Relationship, theirDid: string): Promise<Relationship> {
    if (r.theirDid === theirDid) return r;
    return this.save({ ...r, theirDid });
  }
}
