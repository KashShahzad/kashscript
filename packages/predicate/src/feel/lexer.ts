/**
 * The FEEL subset's lexer. Anything it does not recognise is refused with a
 * message naming what it saw — never skipped.
 */

export type TokenKind = "number" | "string" | "at" | "name" | "punct" | "op" | "eof";

export interface Token {
  readonly kind: TokenKind;
  readonly text: string;
  /** For `string` and `at`: the decoded string. */
  readonly value?: string;
  readonly pos: number;
}

export class FeelSyntaxError extends Error {
  constructor(
    message: string,
    readonly pos: number,
    /** True when the input is FEEL, but outside the subset — refused, not malformed. */
    readonly outsideSubset = false,
  ) {
    super(message);
    this.name = "FeelSyntaxError";
  }
}

const NAME_START = /[A-Za-z_]/;
const NAME_PART = /[A-Za-z0-9_]/;
const DIGIT = /[0-9]/;

function decodeString(src: string, start: number): { value: string; end: number } {
  let i = start + 1;
  let out = "";
  while (i < src.length) {
    const ch = src[i]!;
    if (ch === '"') return { value: out, end: i + 1 };
    if (ch === "\\") {
      const nx = src[i + 1];
      switch (nx) {
        case '"':
        case "'":
        case "\\":
          out += nx;
          i += 2;
          continue;
        case "n":
          out += "\n";
          i += 2;
          continue;
        case "r":
          out += "\r";
          i += 2;
          continue;
        case "t":
          out += "\t";
          i += 2;
          continue;
        case "u": {
          const hex = src.slice(i + 2, i + 6);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new FeelSyntaxError("a \\u escape needs four hex digits", i);
          out += String.fromCharCode(Number.parseInt(hex, 16));
          i += 6;
          continue;
        }
        case "U": {
          const hex = src.slice(i + 2, i + 8);
          if (!/^[0-9a-fA-F]{6}$/.test(hex)) throw new FeelSyntaxError("a \\U escape needs six hex digits", i);
          out += String.fromCodePoint(Number.parseInt(hex, 16));
          i += 8;
          continue;
        }
        default:
          throw new FeelSyntaxError(`unknown escape \\${nx ?? ""}`, i);
      }
    }
    out += ch;
    i += 1;
  }
  throw new FeelSyntaxError("a string is not closed", start);
}

export function lex(src: string): Token[] {
  const out: Token[] = [];
  let i = 0;
  while (i < src.length) {
    const ch = src[i]!;
    if (/\s/.test(ch)) {
      i += 1;
      continue;
    }
    if (ch === "/" && (src[i + 1] === "/" || src[i + 1] === "*")) {
      throw new FeelSyntaxError("comments are not in the subset", i, true);
    }
    if (DIGIT.test(ch) || (ch === "." && DIGIT.test(src[i + 1] ?? ""))) {
      let j = i;
      while (j < src.length && DIGIT.test(src[j]!)) j++;
      if (src[j] === "." && DIGIT.test(src[j + 1] ?? "")) {
        j++;
        while (j < src.length && DIGIT.test(src[j]!)) j++;
      }
      if (/[eE]/.test(src[j] ?? "") && /[0-9+-]/.test(src[j + 1] ?? "")) {
        throw new FeelSyntaxError("number exponents are not in the subset", j, true);
      }
      out.push({ kind: "number", text: src.slice(i, j), pos: i });
      i = j;
      continue;
    }
    if (ch === '"') {
      const { value, end } = decodeString(src, i);
      out.push({ kind: "string", text: src.slice(i, end), value, pos: i });
      i = end;
      continue;
    }
    if (ch === "@") {
      if (src[i + 1] !== '"') throw new FeelSyntaxError("@ must be followed by a string literal", i);
      const { value, end } = decodeString(src, i + 1);
      out.push({ kind: "at", text: src.slice(i, end), value, pos: i });
      i = end;
      continue;
    }
    if (NAME_START.test(ch)) {
      let j = i + 1;
      while (j < src.length && NAME_PART.test(src[j]!)) j++;
      out.push({ kind: "name", text: src.slice(i, j), pos: i });
      i = j;
      continue;
    }
    const two = src.slice(i, i + 2);
    if (two === "**") throw new FeelSyntaxError("exponentiation (**) is not in the subset", i, true);
    if (two === "..") {
      out.push({ kind: "punct", text: "..", pos: i });
      i += 2;
      continue;
    }
    if (two === "!=" || two === "<=" || two === ">=") {
      out.push({ kind: "op", text: two, pos: i });
      i += 2;
      continue;
    }
    if ("+-*/=<>".includes(ch)) {
      out.push({ kind: "op", text: ch, pos: i });
      i += 1;
      continue;
    }
    if ("()[],.:".includes(ch)) {
      out.push({ kind: "punct", text: ch, pos: i });
      i += 1;
      continue;
    }
    if (ch === "{" || ch === "}") throw new FeelSyntaxError("context literals are not in the subset", i, true);
    if (ch === "?") throw new FeelSyntaxError("the implicit input (?) is not in the subset", i, true);
    throw new FeelSyntaxError(`unexpected character ${JSON.stringify(ch)}`, i, /[^\x00-\x7f]/.test(ch));
  }
  out.push({ kind: "eof", text: "", pos: src.length });
  return out;
}
