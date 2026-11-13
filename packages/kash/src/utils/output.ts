/**
 * Tiny ANSI helpers for consistent CLI output.
 * Zero-dependency: just escape sequences and a TTY-detection guard.
 */

const isTty = typeof process !== "undefined" && process.stdout?.isTTY === true;

function wrap(code: number, close: number) {
  return (s: string): string => (isTty ? `[${code}m${s}[${close}m` : s);
}

export const c = {
  bold:    wrap(1,  22),
  dim:     wrap(2,  22),
  red:     wrap(31, 39),
  green:   wrap(32, 39),
  yellow:  wrap(33, 39),
  blue:    wrap(34, 39),
  magenta: wrap(35, 39),
  cyan:    wrap(36, 39),
  gray:    wrap(90, 39),
};

export function info(msg: string):    void { process.stdout.write(`${c.cyan("◆")} ${msg}\n`); }
export function success(msg: string): void { process.stdout.write(`${c.green("✓")} ${msg}\n`); }
export function warn(msg: string):    void { process.stdout.write(`${c.yellow("!")} ${msg}\n`); }
export function fail(msg: string):    void { process.stderr.write(`${c.red("✗")} ${msg}\n`); }
export function step(msg: string):    void { process.stdout.write(`${c.gray("·")} ${c.dim(msg)}\n`); }

export function banner(title: string): void {
  process.stdout.write(`\n${c.bold(title)}\n${c.gray("─".repeat(Math.min(title.length, 60)))}\n`);
}
