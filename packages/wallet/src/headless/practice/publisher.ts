/**
 * A practice trust-list publisher — the role the platform plays for real
 * (PL-7). Its list names issuers and the exact types each may issue; a wallet
 * treats it as trusted only because the practice run pins its identifier.
 */

import { generateKeyPair, deriveDid, type KashKeyPair } from "@kashscript/identity-core";
import type { DsseEnvelope } from "@kashscript/attest/dsse";
import { signTrustList, TRUST_LIST_FORMAT } from "@kashscript/attest/holder";
import type { Clock } from "../../platform";

const DAY = 86_400;

export class PracticePublisher {
  readonly did: string;
  private version = 0;

  private constructor(
    private readonly key: KashKeyPair,
    private readonly now: Clock,
  ) {
    this.did = deriveDid(key.publicKey);
  }

  static async create(now: Clock): Promise<PracticePublisher> {
    return new PracticePublisher(await generateKeyPair(), now);
  }

  async list(issuers: readonly { did: string; label: string; dsts: readonly string[] }[]): Promise<DsseEnvelope> {
    const now = this.now();
    this.version++;
    return signTrustList(
      {
        format: TRUST_LIST_FORMAT,
        listId: "practice-trust-list",
        version: this.version,
        publisher: this.did,
        issuedAtUnix: now,
        validFromUnix: now - DAY,
        validUntilUnix: now + 365 * DAY,
        issuers: issuers.map((i) => ({ issuerId: i.did, label: i.label, keys: [], dsts: [...i.dsts], validFromUnix: now - DAY, validUntilUnix: now + 365 * DAY })),
      },
      { keyid: this.did, privateKey: this.key.privateKey, publicKey: this.key.publicKey },
    );
  }
}
