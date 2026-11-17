/**
 * A practice trust-list publisher — the role the platform plays for real
 * (PL-7). Its list names issuers and the exact types each may issue; a wallet
 * treats it as trusted only because the practice run pins its identifier.
 */

import { generateKeyPair, deriveDid, type KashKeyPair } from "@kashscript/identity-core";
import type { DsseEnvelope } from "@kashscript/attest/dsse";
import { signTrustList, TRUST_LIST_FORMAT, type IssuerClass, type Standing } from "@kashscript/attest/holder";
import type { Clock } from "../../platform";

const DAY = 86_400;

/** One entry as the practice publisher writes it — d91's three assertions included (KS-Q4). */
export interface PracticeListEntry {
  readonly did: string;
  readonly label: string;
  readonly dsts: readonly string[];
  /** Default `counterparty`. */
  readonly class?: IssuerClass;
  /** Default `listed`. A suspended or removed entry ends its window when written, as lexicons' guard asks. */
  readonly standing?: Standing;
  /** Default 1: the minimum for a paying customer (d91(d)). */
  readonly grade?: 0 | 1 | 2 | 3;
}

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

  async list(issuers: readonly PracticeListEntry[]): Promise<DsseEnvelope> {
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
        floor: { version: "practice floor" },
        practice: true,
        issuers: issuers.map((i) => {
          const standing = i.standing ?? "listed";
          return {
            issuerId: i.did,
            label: i.label,
            keys: [],
            dsts: [...i.dsts],
            validFromUnix: now - DAY,
            // A suspended or removed entry's window ends no later than the list's time (lexicons' STANDING_WINDOW).
            validUntilUnix: standing === "listed" ? now + 365 * DAY : now,
            class: i.class ?? "counterparty",
            standing,
            grade: i.grade ?? 1,
          };
        }),
      },
      { keyid: this.did, privateKey: this.key.privateKey, publicKey: this.key.publicKey },
    );
  }
}
