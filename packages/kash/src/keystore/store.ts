/**
 * The keystore: an organisation's own keys, in files it holds (d47 — never a
 * private key on a server). One key per file, `<name>.key.json`:
 *
 *   { format: "kash-key/1", name, did, createdAt, jwk }     jwk = RFC 8037 Ed25519 (x, d)
 *
 * The key is plaintext JSON. The only things guarding it are the file system's
 * owner-only permissions (see ./permissions.ts) and where the file lives. There
 * is no recovery: a lost file is a new DID.
 *
 * A key file is never read from, or written to, anywhere but the local disk.
 */

import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { deriveDid, exportKey, generateKeyPair, importKey, type ExportedKey } from "@kashscript/identity-core";

import { KashCliError } from "../errors";
import { keystoreDir } from "../utils/paths";
import { checkProtection, fixHint, protect, type Protection } from "./permissions";

export const KEY_FORMAT = "kash-key/1" as const;
const NAME = /^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/;
const SUFFIX = ".key.json";

interface KeyFile {
  readonly format: typeof KEY_FORMAT;
  readonly name: string;
  readonly did: string;
  readonly createdAt: string;
  readonly jwk: ExportedKey;
}

/** A key loaded for signing. Hold it only as long as the command runs. */
export interface KeyHandle {
  readonly name: string;
  readonly path: string;
  readonly did: string;
  readonly publicKey: Uint8Array;
  /** SECRET. */
  readonly privateKey: Uint8Array;
}

export interface CreatedKey {
  readonly name: string;
  readonly path: string;
  readonly did: string;
  /** The key file. */
  readonly file: Protection;
  /** The folder, when this call created it; null when it already existed and was left as it was. */
  readonly folder: Protection | null;
}

export interface ListedKey {
  readonly name: string;
  readonly path: string;
  readonly did: string | null;
  readonly problem: string | null;
  readonly protection: Protection;
}

/** The one place a secret is written. A seam so a test can make the write fail and see the file taken away again. */
export const fileIO = {
  writeSecret(path: string, text: string): void {
    writeFileSync(path, text, { mode: 0o600 });
  },
};

export function assertKeyName(name: string): void {
  if (!NAME.test(name)) {
    throw new KashCliError(
      `Key name ${JSON.stringify(name)} is not allowed: use letters, digits, "-" or "_", up to 32 characters.`,
      "INVALID_INPUT",
    );
  }
}

/** A bare name is `<keystore>/<name>.key.json`; anything with a separator, or ending `.json`, is a path. */
export function resolveKeyPath(ref: string, keystore?: string): string {
  if (ref === "") throw new KashCliError("A key name or path is needed.", "INVALID_INPUT");
  if (/[\\/]/.test(ref) || ref.endsWith(".json")) return resolve(ref);
  assertKeyName(ref);
  return join(keystoreDir(keystore), `${ref}${SUFFIX}`);
}

/**
 * Make a new key. Refuses to overwrite one. The file is created empty, locked to
 * its owner, and only then given the secret — so the secret is never written to a
 * file anyone else can read. The folder is tightened only when this call created
 * it: a folder that already existed may be someone's, and is left as it was.
 */
export async function createKey(name: string, keystore?: string): Promise<CreatedKey> {
  assertKeyName(name);
  const dir = keystoreDir(keystore);
  const path = join(dir, `${name}${SUFFIX}`);
  if (existsSync(path)) {
    throw new KashCliError(
      `A key named "${name}" already exists at ${path}. kash never overwrites a key; move it aside if you mean to replace it.`,
      "KEY_EXISTS",
    );
  }

  let folder: Protection | null = null;
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    folder = protect(dir, "dir");
  }

  const pair = await generateKeyPair();
  const did = deriveDid(pair.publicKey);
  const body: KeyFile = { format: KEY_FORMAT, name, did, createdAt: new Date().toISOString(), jwk: exportKey(pair) };

  try {
    writeFileSync(path, "", { flag: "wx", mode: 0o600 });
  } catch (err) {
    throw new KashCliError(`Could not create ${path}: ${(err as Error).message}`, "KEY_EXISTS", err);
  }
  // From here the empty file is ours. If anything fails before the secret is in it, take it away again:
  // a zero-byte file would otherwise block this name for good ("kash never overwrites a key").
  try {
    const file = protect(path, "file");
    fileIO.writeSecret(path, JSON.stringify(body, null, 2) + "\n");
    return { name, path, did, file, folder };
  } catch (err) {
    try {
      rmSync(path, { force: true });
    } catch {
      /* nothing more can be done; the original error is the one to report */
    }
    throw new KashCliError(`Could not write the key to ${path}: ${(err as Error).message}. Nothing was left behind.`, "KEY_INVALID", err);
  }
}

/** Load a key by name or path. Checks the DID is the one the key derives. Refuses a key others can read (POSIX). */
export async function loadKey(ref: string, keystore?: string): Promise<KeyHandle> {
  const path = resolveKeyPath(ref, keystore);
  if (!existsSync(path)) {
    throw new KashCliError(
      `No key at ${path}. Make one with \`kash station init --name ${NAME.test(ref) ? ref : "<name>"}\`, or pass --key <path>.`,
      "KEY_NOT_FOUND",
    );
  }
  // A key others can use is not one to sign with. "Could not tell" is a warning, not a stop:
  // it must not turn a flaky read-back into a reason nobody can sign.
  const protection = checkProtection(path, "file");
  if (protection.state === "exposed") {
    throw new KashCliError(`${path} is not private to you (${protection.detail}). Fix it with: ${fixHint(path)}`, "KEY_UNPROTECTED");
  }
  if (protection.state === "unknown") {
    process.stderr.write(`! ${path} is not confirmed private to you (${protection.detail}). Carrying on.\n`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    throw new KashCliError(`${path} is not valid JSON.`, "KEY_INVALID", err);
  }
  const f = parsed as Partial<KeyFile>;
  if (f?.format !== KEY_FORMAT || typeof f.did !== "string" || typeof f.jwk !== "object" || f.jwk === null) {
    throw new KashCliError(`${path} is not a ${KEY_FORMAT} file.`, "KEY_INVALID");
  }
  let pair;
  try {
    pair = await importKey(f.jwk);
  } catch (err) {
    throw new KashCliError(`${path} holds a key that does not check out: ${(err as Error).message}`, "KEY_INVALID", err);
  }
  const derived = deriveDid(pair.publicKey);
  if (derived !== f.did) {
    throw new KashCliError(`${path} says its DID is ${f.did}, but its key derives ${derived}. Refusing to sign with it.`, "KEY_INVALID");
  }
  // The name comes from the file's own name, never from its contents: it is shown to a person who is
  // deciding whether to sign, so it must not be text an edited key file can choose. Control characters
  // (an escape sequence in a file name) are shown as "?".
  const name = basename(path).replace(/\.key\.json$|\.json$/, "").replace(/[^\x20-\x7e]/g, "?");
  return { name, path, did: derived, publicKey: pair.publicKey, privateKey: pair.privateKey };
}

/** Every `*.key.json` in the keystore, with whether each is still owner-only. Does not decode the secret. */
export function listKeys(keystore?: string): readonly ListedKey[] {
  const dir = keystoreDir(keystore);
  if (!existsSync(dir)) return [];
  const out: ListedKey[] = [];
  for (const entry of readdirSync(dir).sort()) {
    if (!entry.endsWith(SUFFIX)) continue;
    const path = join(dir, entry);
    let did: string | null = null;
    let problem: string | null = null;
    try {
      const f = JSON.parse(readFileSync(path, "utf8")) as Partial<KeyFile>;
      if (f.format === KEY_FORMAT && typeof f.did === "string") did = f.did;
      else problem = `not a ${KEY_FORMAT} file`;
    } catch {
      problem = "not valid JSON";
    }
    out.push({ name: basename(entry, SUFFIX), path, did, problem, protection: checkProtection(path, "file") });
  }
  return out;
}
