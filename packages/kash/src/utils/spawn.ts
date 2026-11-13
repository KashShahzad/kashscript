/**
 * Starting a package manager (npm, pnpm, yarn, bun, bunx) on every platform.
 *
 * On Windows most of these are `.cmd` shims, and a `.cmd` always runs under
 * cmd.exe: Node refuses to start one without `shell` (CVE-2024-27980), and Bun
 * 1.2 starts one itself but hands cmd.exe any argument without a space raw.
 * Either way cmd.exe reads ^ & | < > as its own — `pkg@^0.1.0` loses its caret,
 * `pkg@>=1` redirects into a file. So on Windows every argument is
 * double-quoted, inside which cmd.exe takes those as text, and an argument it
 * cannot quote safely is refused. Elsewhere there is no shell at all.
 */

import { spawn, type ChildProcess, type SpawnOptions } from "node:child_process";

import { KashCliError } from "../errors";

/** A command is one of kash's own fixed names, never a path or input. */
const COMMAND = /^[a-z][a-z0-9-]*$/;
/** cmd.exe still reads these inside double quotes (or the quote ends early). */
const UNQUOTABLE = /["%!\r\n]|\\$/;

/** The arguments as cmd.exe must receive them on Windows; unchanged elsewhere. */
export function managerArgs(args: readonly string[], platform: NodeJS.Platform = process.platform): string[] {
  if (platform !== "win32") return [...args];
  return args.map((a) => {
    if (UNQUOTABLE.test(a)) {
      throw new KashCliError(
        `Refusing to pass ${JSON.stringify(a)} to a package manager: cmd.exe cannot be given it safely.`,
        "INVALID_INPUT",
      );
    }
    return `"${a}"`;
  });
}

/** Spawn a package manager: through cmd.exe on Windows (arguments quoted), directly elsewhere. */
export function spawnManager(cmd: string, args: readonly string[], opts: Omit<SpawnOptions, "shell"> = {}): ChildProcess {
  if (!COMMAND.test(cmd)) throw new KashCliError(`Not a package manager command: ${JSON.stringify(cmd)}.`, "INVALID_INPUT");
  const quoted = managerArgs(args);
  // The shell is Windows-only, for .cmd shims; the command is checked against
  // COMMAND (a fixed name, never a path or input) and every argument is quoted
  // by managerArgs above (see the header).
  // nosemgrep: javascript.lang.security.audit.spawn-shell-true.spawn-shell-true, javascript.lang.security.detect-child-process.detect-child-process
  return spawn(cmd, quoted, { ...opts, shell: process.platform === "win32" });
}
