/**
 * `kash status` — the keystore and the environment fingerprint.
 *
 * Reports each key's name and DID, and whether its file is still owner-only —
 * read back now, not remembered from when it was made. There is no session to
 * report: kash holds no login.
 */

import { listKeys } from "../keystore/store";
import { keystoreDir } from "../utils/paths";
import { banner, c, info, step, warn } from "../utils/output";
import { formatReport, scanEnvironment } from "../utils/env";

export interface StatusOptions {
  readonly keystore?: string;
}

export async function runStatus(opts: StatusOptions = {}): Promise<void> {
  banner("kash · status");

  const dir = keystoreDir(opts.keystore);
  const keys = listKeys(opts.keystore);
  if (keys.length === 0) {
    warn(`No keys in ${dir}. Make one with \`kash station init\`.`);
  } else {
    info(`Keystore ${c.bold(dir)}`);
    for (const k of keys) {
      process.stdout.write(`  ${c.bold(k.name)}  ${k.did ?? c.red(`(${k.problem ?? "unreadable"})`)}\n`);
      if (k.protection.confirmed) step(`private to you — ${k.protection.detail}`);
      else warn(`${c.red("not confirmed private")} — ${k.protection.detail}`);
    }
  }

  process.stdout.write("\n");
  try {
    const report = await scanEnvironment();
    process.stdout.write(formatReport(report) + "\n");
  } catch (err) {
    warn(`Could not scan environment: ${(err as Error).message}`);
  }
}
