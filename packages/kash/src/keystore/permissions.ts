/**
 * Owner-only permissions for key files — and a check that they took.
 *
 * A key file is the whole of a station's authority (d47: never on a server, so
 * the file system is the only guard it has). Protection is therefore reported
 * as *confirmed* only when it was read back after being set; anything else is
 * said plainly, never assumed (d11).
 *
 * - POSIX: directory 0700, file 0600, re-stat'd.
 * - Windows: `chmod` only toggles the read-only bit, so the ACL is set with
 *   `icacls` (inheritance removed, one grant to the current user's SID) and
 *   read back with `icacls /save`, which writes the DACL as SDDL — SIDs and
 *   flags, so nothing depends on localised account names. Removing inherited
 *   entries also removes SYSTEM and Administrators from that file or folder.
 *
 * Three states, not two, because "I could not tell" and "someone else can read
 * it" call for different responses:
 *   private  — read back, and owner-only. Reported as `confirmed`.
 *   exposed  — read back, and someone beyond the owner (and, on Windows, SYSTEM
 *              and Administrators, who can take ownership of anything anyway)
 *              can use it. Loading a key in this state is refused.
 *   unknown  — could not be read back, or is the owner's alone only by
 *              inheritance. Loading warns and goes on.
 *
 * Nothing here touches the network. `spawnSync` without a shell, so paths with
 * spaces are passed intact.
 */

import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export type ProtectionState = "private" | "exposed" | "unknown";

export interface Protection {
  readonly state: ProtectionState;
  /** Read back after being set, and found to be owner-only (`state === "private"`). */
  readonly confirmed: boolean;
  readonly method: "posix-mode" | "windows-acl" | "none";
  /** One plain sentence a person can read. */
  readonly detail: string;
}

const IS_WINDOWS = process.platform === "win32";

/**
 * Windows' own tools, by absolute path. Git Bash and MSYS put a POSIX `whoami` ahead of System32 on PATH; it does
 * not know `/user`, so the SID read fails and the access list is never set — the key file keeps its inherited ACL.
 */
const SYSTEM32 = join(process.env.SystemRoot ?? process.env.windir ?? "C:\\Windows", "System32");
const WHOAMI = join(SYSTEM32, "whoami.exe");
const ICACLS = join(SYSTEM32, "icacls.exe");

function result(state: ProtectionState, method: Protection["method"], detail: string): Protection {
  return { state, confirmed: state === "private", method, detail };
}

function run(cmd: string, args: readonly string[]): { status: number | null; stdout: string; stderr: string } {
  // `cmd` is WHOAMI or ICACLS above (absolute System32 paths), never input; no shell.
  // nosemgrep: javascript.lang.security.detect-child-process.detect-child-process
  const r = spawnSync(cmd, [...args], { encoding: "utf8", windowsHide: true });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

/* ── Windows ─────────────────────────────────────────────────────────────── */

let cachedSid: string | null | undefined;

/** The current user's SID, from `whoami /user`. Null if it cannot be read. */
export function currentSid(): string | null {
  if (cachedSid !== undefined) return cachedSid;
  const r = run(WHOAMI, ["/user", "/fo", "csv", "/nh"]);
  const m = /S-1-\d+(?:-\d+)+/.exec(r.stdout);
  cachedSid = r.status === 0 && m !== null ? m[0] : null;
  return cachedSid;
}

/** The DACL of `path` as SDDL, via `icacls /save` (UTF-16LE on disk). Null if it cannot be read. */
function readSddl(path: string): string | null {
  const scratch = mkdtempSync(join(tmpdir(), "kash-acl-"));
  try {
    const out = join(scratch, "acl.txt");
    const r = run(ICACLS, [path, "/save", out]);
    if (r.status !== 0) return null;
    const text = readFileSync(out).toString("utf16le").replace(/^﻿/, "");
    const at = text.indexOf("D:");
    return at === -1 ? null : text.slice(at).trim();
  } catch {
    return null;
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

interface Ace {
  readonly type: string;
  readonly flags: string;
  readonly trustee: string;
}

/** The DACL's flags (`P` = protected from inheritance) and entries. */
function parseSddl(sddl: string): { readonly flags: string; readonly aces: readonly Ace[] } {
  const flags = /^D:([A-Z]*)(?:\(|$)/.exec(sddl)?.[1] ?? "";
  const aces = [...sddl.matchAll(/\(([^()]*)\)/g)].map((m) => {
    const f = (m[1] ?? "").split(";");
    return { type: f[0] ?? "", flags: f[1] ?? "", trustee: f[5] ?? "" };
  });
  return { flags, aces };
}

/**
 * Is this SDDL trustee the owner? `icacls /save` writes a SID string, except that
 * SDDL has short names for a few well-known accounts: the built-in Administrator
 * account (RID 500) is `LA`, and `OW` / `CO` mean "the owner" / "the creator".
 */
function isOwner(trustee: string, sid: string): boolean {
  return trustee === sid || trustee === "OW" || trustee === "CO" || (trustee === "LA" && sid.endsWith("-500"));
}

/** SYSTEM and Administrators: present on most folders by default, and able to take ownership of anything. */
const ADMIN_TRUSTEES = new Set(["SY", "BA"]);

function windowsCheck(path: string): Protection {
  const sid = currentSid();
  const sddl = readSddl(path);
  if (sid === null || sddl === null) {
    return result("unknown", "windows-acl", "the access list could not be read back, so protection is not confirmed");
  }
  return classifySddl(sddl, sid);
}

/** Judge a DACL (as `icacls /save` writes it) for the account whose SID is `sid`. Pure, so it can be tested with any ACL. */
export function classifySddl(sddl: string, sid: string): Protection {
  const { flags, aces } = parseSddl(sddl);
  const allows = aces.filter((a) => a.type === "A" || a.type === "OA");
  const others = allows.filter((a) => !isOwner(a.trustee, sid) && !ADMIN_TRUSTEES.has(a.trustee));
  if (others.length > 0) {
    return result("exposed", "windows-acl", "the access list lets accounts other than yours (or SYSTEM and Administrators) use this");
  }
  const ownerOnly = flags.includes("P") && allows.length === 1 && allows.every((a) => isOwner(a.trustee, sid) && !a.flags.includes("ID"));
  return ownerOnly
    ? result("private", "windows-acl", "access list holds your account only; inherited entries removed")
    : result("unknown", "windows-acl", "only you, SYSTEM and Administrators can use this, but it is not locked to your account alone");
}

function windowsProtect(path: string, kind: "file" | "dir"): Protection {
  const sid = currentSid();
  if (sid === null) {
    return result("unknown", "windows-acl", "could not read your account's SID (whoami /user), so the access list was not changed");
  }
  const grant = kind === "dir" ? `*${sid}:(OI)(CI)F` : `*${sid}:F`;
  const set = run(ICACLS, [path, "/inheritance:r", "/grant:r", grant]);
  if (set.status !== 0) {
    return result("unknown", "windows-acl", `icacls refused to set the access list (${(set.stderr || set.stdout).trim().split("\n")[0] ?? "no message"})`);
  }
  return windowsCheck(path);
}

/* ── POSIX ───────────────────────────────────────────────────────────────── */

function posixCheck(path: string, kind: "file" | "dir"): Protection {
  try {
    const mode = statSync(path).mode & 0o777;
    if ((mode & 0o077) === 0) {
      return result("private", "posix-mode", `mode ${mode.toString(8)} — no group or other access`);
    }
    return result("exposed", "posix-mode", `mode ${mode.toString(8)} — group or other can access this ${kind}`);
  } catch (err) {
    return result("unknown", "posix-mode", `could not read the mode (${(err as Error).message})`);
  }
}

function posixProtect(path: string, kind: "file" | "dir"): Protection {
  try {
    chmodSync(path, kind === "dir" ? 0o700 : 0o600);
  } catch (err) {
    return result("unknown", "posix-mode", `chmod failed (${(err as Error).message})`);
  }
  return posixCheck(path, kind);
}

/* ── public ──────────────────────────────────────────────────────────────── */

/** Restrict `path` to its owner and read the result back. Never throws; the result says what held. */
export function protect(path: string, kind: "file" | "dir"): Protection {
  return IS_WINDOWS ? windowsProtect(path, kind) : posixProtect(path, kind);
}

/** Read back whether `path` is owner-only, without changing it. */
export function checkProtection(path: string, kind: "file" | "dir"): Protection {
  return IS_WINDOWS ? windowsCheck(path) : posixCheck(path, kind);
}

/** The command that would fix `path`, for an error message. */
export function fixHint(path: string): string {
  if (IS_WINDOWS) {
    const sid = currentSid();
    return sid === null ? `icacls "${path}" /inheritance:r /grant:r "<your account>:F"` : `icacls "${path}" /inheritance:r /grant:r "*${sid}:F"`;
  }
  return `chmod 600 "${path}"`;
}
