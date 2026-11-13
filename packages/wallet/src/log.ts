/**
 * The presentation log — the holder's own record of what they showed, and to
 * whom (d42 §2; presentation §5). Kept in the vault, exported with the wallet,
 * never sent anywhere, and part of no presentation. It holds presentations and
 * the holder's own excessive-ask notes. **A decline has no entry**: declining
 * emits nothing and writes nothing (d49(a)).
 */

import { validatePresentationLog, type PresentationLogEntry } from "@kashscript/attest/exchange";
import { WalletError } from "./errors";
import { LOG, type Vault } from "./vault";

export class PresentationLog {
  constructor(private readonly vault: Vault) {}

  async list(): Promise<readonly PresentationLogEntry[]> {
    return (await this.vault.get<PresentationLogEntry[]>(LOG)) ?? [];
  }

  /** Append, refusing anything that would make the log say a copy or key was shown to two verifiers. */
  async append(...entries: readonly PresentationLogEntry[]): Promise<void> {
    const next = [...(await this.list()), ...entries];
    const check = validatePresentationLog(next);
    if (!check.ok) throw new WalletError("VAULT_CORRUPT", check.violations.map((v) => v.code).join(", "));
    await this.vault.put(LOG, next);
  }
}
