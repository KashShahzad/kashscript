/**
 * Every refusal the wallet makes, with a message in plain words. An app may
 * show `message` to a person, so every message obeys the copy rule (d44): no
 * ecosystem or member name, and no word a person must learn first. The
 * machine-readable reason is `code`; `detail` is for developers only.
 */

export type WalletErrorCode =
  | "LOCKED"
  | "ROOT_UNAVAILABLE"
  | "ROOT_LOST"
  | "VAULT_CORRUPT"
  | "NEEDS_CHOICE"
  | "SWITCH_OFF"
  | "OFFER_INVALID"
  | "OFFER_ORIGIN"
  | "ISSUER_REFUSED"
  | "RECORD_REFUSED"
  | "REQUEST_INVALID"
  | "ASK_REFUSED"
  | "DOOR_REFUSED"
  | "NOT_ANSWERABLE"
  | "REDEEM_ELSEWHERE"
  | "LINE_REFUSED"
  | "SIGN_REFUSED"
  | "NOT_FOUND"
  | "IDENTIFIER_LEAK"
  | "NOT_HTTPS"
  | "OFFLINE"
  | "SEND_FAILED"
  | "BACKUP_INVALID"
  | "BACKUP_PASSPHRASE"
  | "WEAK_PASSPHRASE"
  | "EXPORT_INVALID"
  | "IMPORT_INVALID"
  | "RECOVERY_HELPERS_INVALID"
  | "RECOVERY_ALREADY_HELPING"
  | "RECOVERY_NOT_YOURS"
  | "RECOVERY_NOTHING_TO_RECOVER"
  | "RECOVERY_NOT_STARTED"
  | "RUNTIME_UNSUPPORTED"
  | "PRACTICE_ONLY"
  | "WEAKER_NOT_ACKNOWLEDGED";

/** The words a person may see. Tested against the banned-word list. */
export const ERROR_MESSAGES: Readonly<Record<WalletErrorCode, string>> = {
  LOCKED: "Unlock your records first.",
  ROOT_UNAVAILABLE: "This device can't keep your keys safely.",
  ROOT_LOST: "This device can no longer open your records. Bring them back from a file you saved.",
  VAULT_CORRUPT: "Your records on this device can't be read.",
  NEEDS_CHOICE: "Choose first whether to keep a record with this place.",
  SWITCH_OFF: "You chose not to keep records with this place. Nothing was sent.",
  OFFER_INVALID: "This code or link can't be read.",
  OFFER_ORIGIN: "This link points somewhere other than the place that made it, so it wasn't opened.",
  ISSUER_REFUSED: "The place didn't hand over the record. The code may be used up or out of date.",
  RECORD_REFUSED: "What arrived didn't check out, so it wasn't kept.",
  REQUEST_INVALID: "This request can't be read.",
  ASK_REFUSED: "This request breaks the rules for asking, so it can't be answered.",
  DOOR_REFUSED: "This rule doesn't check out, or isn't in force, so nothing was shown or sent.",
  NOT_ANSWERABLE: "You don't hold what this request needs.",
  REDEEM_ELSEWHERE: "A thank-you can only be used with whoever gave it.",
  LINE_REFUSED: "This line doesn't check out, so it wasn't signed.",
  SIGN_REFUSED: "This can't be signed from here, so it wasn't.",
  NOT_FOUND: "That isn't in your records.",
  IDENTIFIER_LEAK: "Stopped before sending: it would have told one place about another.",
  NOT_HTTPS: "Stopped before sending: the address isn't secure.",
  OFFLINE: "You're offline. Nothing was sent.",
  SEND_FAILED: "It couldn't be sent. Nothing was changed.",
  BACKUP_INVALID: "This backup can't be read.",
  BACKUP_PASSPHRASE: "That passphrase doesn't open this backup.",
  WEAK_PASSPHRASE: "Choose a longer passphrase, at least 8 characters.",
  EXPORT_INVALID: "The file didn't check out, so it wasn't made.",
  IMPORT_INVALID: "This file didn't check out, so nothing was brought in.",
  RECOVERY_HELPERS_INVALID: "These helpers can't be used. Choose at least two people, and more than half of them must agree.",
  RECOVERY_ALREADY_HELPING: "You already help this person from this phone.",
  RECOVERY_NOT_YOURS: "This request isn't from anyone you help.",
  RECOVERY_NOTHING_TO_RECOVER: "This file holds nothing your helpers can bring back. It was saved before you chose helpers.",
  RECOVERY_NOT_STARTED: "Start getting your keys back first.",
  RUNTIME_UNSUPPORTED: "This app is missing something it needs to keep your keys safe.",
  PRACTICE_ONLY: "This is for practice runs only, never for real records.",
  WEAKER_NOT_ACKNOWLEDGED: "A browser keeps keys less safely than a phone. Say you understand before using it.",
};

export class WalletError extends Error {
  override readonly name = "WalletError";
  readonly code: WalletErrorCode;
  /** For developers: attest reasons, HTTP status, what was missing. Never shown by default. */
  readonly detail: string | null;

  constructor(code: WalletErrorCode, detail: string | null = null) {
    super(ERROR_MESSAGES[code]);
    this.code = code;
    this.detail = detail;
    Object.setPrototypeOf(this, WalletError.prototype);
  }
}

export function isWalletError(e: unknown, code?: WalletErrorCode): e is WalletError {
  return e instanceof WalletError && (code === undefined || e.code === code);
}
