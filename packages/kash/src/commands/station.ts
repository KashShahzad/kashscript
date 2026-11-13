/**
 * `kash station init` — make an organisation's own key, in its own keystore.
 *
 * "Station" is the name of the first use; the key is any organisation's own
 * (`--name teacher` for the teacher's organisation, `--name publisher` for the
 * key that signs trust lists). The DID printed is the one a charter or a record
 * will name (d62(d)2): organisations sign as themselves, never with a key made
 * per ceremony.
 *
 * Local only (d47): the key is made here, stays here, and nothing is sent anywhere.
 */

import { createKey } from "../keystore/store";
import { banner, c, info, step, success, warn } from "../utils/output";

export interface StationInitOptions {
  /** The key's name in the keystore. Default `station`. */
  readonly name?: string;
  readonly keystore?: string;
}

export async function runStationInit(opts: StationInitOptions = {}): Promise<void> {
  const name = opts.name ?? "station";
  banner("kash · station init");

  const made = await createKey(name, opts.keystore);

  success(`Made the key ${c.bold(name)}.`);
  process.stdout.write(`  did      : ${made.did}\n`);
  process.stdout.write(`  key file : ${made.path}\n`);

  if (made.file.confirmed) {
    step(`Protection confirmed: ${made.file.detail}.`);
  } else {
    warn(`${c.red("This key file is NOT confirmed private to you")}: ${made.file.detail}. Fix that before you rely on it.`);
  }
  if (made.folder !== null && !made.folder.confirmed) {
    warn(`The new keystore folder is not confirmed private either: ${made.folder.detail}.`);
  }

  info("This DID is the one a charter or a record will name. Write it where the charter can cite it.");
  step("The key file is plain JSON — only the permissions above guard it. It is not encrypted.");
  step("There is no recovery. If the file is lost, this is a new key and a new DID; nobody can restore it for you.");
  step("Back it up somewhere offline that you control, and never to a server (d47).");
}
