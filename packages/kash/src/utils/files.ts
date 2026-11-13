/**
 * Local files the station commands read and write: records, requests, signed
 * lists. Everything stays on this disk — no command here opens a socket.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

import { KashCliError } from "../errors";

/** Read and parse a JSON file, or say plainly why not. */
export function readJsonFile(path: string, what: string): unknown {
  const abs = resolve(path);
  if (!existsSync(abs)) throw new KashCliError(`${what}: no file at ${abs}.`, "INVALID_INPUT");
  try {
    return JSON.parse(readFileSync(abs, "utf8"));
  } catch (err) {
    throw new KashCliError(`${what}: ${abs} is not valid JSON.`, "INVALID_INPUT", err);
  }
}

/** Write a file the person named. Not a key: ordinary permissions. Refuses to overwrite unless told. */
export function writeOutput(path: string, text: string, overwrite = false): string {
  const abs = resolve(path);
  const exists = (): KashCliError =>
    new KashCliError(`${abs} already exists. Pass --out with another name; kash does not overwrite a record.`, "UNSAFE_WRITE");
  if (!overwrite && existsSync(abs)) throw exists();
  mkdirSync(dirname(abs), { recursive: true });
  try {
    // "wx" creates exclusively, so two runs racing for one name cannot both win.
    writeFileSync(abs, text, { flag: overwrite ? "w" : "wx" });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "EEXIST") throw exists();
    throw err;
  }
  return abs;
}
