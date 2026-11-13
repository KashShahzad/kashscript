/**
 * Filesystem paths used by the CLI.
 *
 * Layout:
 *   ~/.kash/
 *     ├── keys/                (the keystore — owner-only; `kash station init`)
 *     │     └── <name>.key.json
 *     ├── config.json          (overrides etc.)
 *     └── backups/             (rolling backups of mutated files)
 */

import * as os from "node:os";
import * as path from "node:path";

export function configDir(): string {
  return path.join(os.homedir(), ".kash");
}
export function configFile(): string {
  return path.join(configDir(), "config.json");
}
export function backupsDir(): string {
  return path.join(configDir(), "backups");
}

/**
 * The keystore: `--keystore <dir>` wins, then `$KASH_KEYSTORE`, then `~/.kash/keys`.
 * A key is never read from, or written to, anywhere a server can reach (d47).
 */
export function keystoreDir(override?: string): string {
  if (override !== undefined && override !== "") return path.resolve(override);
  const fromEnv = process.env["KASH_KEYSTORE"];
  if (fromEnv !== undefined && fromEnv !== "") return path.resolve(fromEnv);
  return path.join(configDir(), "keys");
}
