/**
 * The FEEL subset's parser (DMN 1.5 §10.3.1, literal expressions only).
 *
 * Grammar, lowest precedence first:
 *   expr       := quantified | disjunction
 *   quantified := ("some" | "every") name "in" disjunction ("," name "in" disjunction)* "satisfies" expr
 *   disjunction:= conjunction ("or" conjunction)*
 *   conjunction:= comparison ("and" comparison)*
 *   comparison := additive ( ("=" | "!=" | "<" | "<=" | ">" | ">=") additive
 *                          | "between" additive "and" additive
 *                          | "in" tests )?
 *   additive   := multiplicative (("+" | "-") multiplicative)*
 *   multiplicative := unary (("*" | "/") unary)*
 *   unary      := "-" unary | postfix
 *   postfix    := primary ( "." name | "[" expr "]" | "(" args ")" )*
 *   primary    := number | string | @string | true | false | null | name | builtin | "(" expr ")" | "[" list "]"
 *
 * Everything else FEEL has is refused by name: `for`, `if`, `function`,
 * `instance of`, context literals, ranges as values, `time`, and every
 * builtin not listed in `BUILTINS`.
 */

import { Decimal } from "./decimal";
import { FeelSyntaxError, lex, type Token } from "./lexer";
import { LOCAL_OR_ZONED_DT_RE } from "./temporal";

export type CmpOp = "=" | "!=" | "<" | "<=" | ">" | ">=";
export type ArithOp = "+" | "-" | "*" | "/";

export type Test =
  | { readonly k: "cmp"; readonly op: CmpOp; readonly e: Node }
  | { readonly k: "interval"; readonly lo: Node; readonly hi: Node; readonly loClosed: boolean; readonly hiClosed: boolean }
  | { readonly k: "expr"; readonly e: Node };

export type Node =
  | { readonly k: "num"; readonly v: Decimal }
  | { readonly k: "str"; readonly v: string }
  | { readonly k: "bool"; readonly v: boolean }
  | { readonly k: "null" }
  | { readonly k: "at"; readonly text: string }
  | { readonly k: "name"; readonly name: string; readonly pos: number }
  | { readonly k: "path"; readonly target: Node; readonly name: string }
  | { readonly k: "filter"; readonly target: Node; readonly test: Node }
  | { readonly k: "index"; readonly target: Node; readonly index: Decimal }
  | { readonly k: "call"; readonly fn: Builtin; readonly args: readonly Node[]; readonly named: Readonly<Record<string, Node>> | null }
  | { readonly k: "list"; readonly items: readonly Node[] }
  | { readonly k: "neg"; readonly e: Node }
  | { readonly k: "arith"; readonly op: ArithOp; readonly l: Node; readonly r: Node }
  | { readonly k: "cmp"; readonly op: CmpOp; readonly l: Node; readonly r: Node }
  | { readonly k: "and"; readonly l: Node; readonly r: Node }
  | { readonly k: "or"; readonly l: Node; readonly r: Node }
  | { readonly k: "between"; readonly e: Node; readonly lo: Node; readonly hi: Node }
  | { readonly k: "in"; readonly e: Node; readonly tests: readonly Test[] }
  | { readonly k: "quant"; readonly every: boolean; readonly iters: readonly { readonly name: string; readonly list: Node }[]; readonly satisfies: Node };

/** The builtins in the subset, with their parameter names (for named arguments). */
export const BUILTINS = {
  not: [["negand"]],
  count: [["list"]],
  sum: [["list"], "variadic"],
  min: [["list"], "variadic"],
  max: [["list"], "variadic"],
  "list contains": [["list", "element"]],
  "distinct values": [["list"]],
  date: [["from"], ["year", "month", "day"]],
  "date and time": [["from"]],
  duration: [["from"]],
  "years and months duration": [["from", "to"]],
} as const satisfies Record<string, readonly (readonly string[] | "variadic")[]>;
export type Builtin = keyof typeof BUILTINS;

/** Words FEEL has that the subset does not, each refused with its own message. */
const REFUSED_WORDS: Readonly<Record<string, string>> = {
  for: "`for` loops are not in the subset",
  return: "`for` loops are not in the subset",
  if: "`if … then … else` is not in the subset — a condition is one yes-or-no expression",
  then: "`if … then … else` is not in the subset",
  else: "`if … then … else` is not in the subset",
  function: "function definitions are not in the subset",
  external: "function definitions are not in the subset",
  instance: "`instance of` is not in the subset",
  time: "the `time` type is not in the subset",
  now: "`now()` is not in the subset — it reads a clock; a rule reads `asOf`",
  today: "`today()` is not in the subset — it reads a clock; a rule reads `asOf`",
};

const KEYWORDS = new Set(["and", "or", "between", "in", "some", "every", "satisfies", "true", "false", "null", "not", ...Object.keys(REFUSED_WORDS)]);

const MULTIWORD: readonly (readonly string[])[] = [
  ["date", "and", "time"],
  ["years", "and", "months", "duration"],
  ["list", "contains"],
  ["distinct", "values"],
];

export const MAX_SOURCE_BYTES = 2048;
export const MAX_DEPTH = 32;

class Parser {
  private i = 0;
  private depth = 0;

  constructor(private readonly toks: readonly Token[]) {}

  private peek(o = 0): Token {
    return this.toks[Math.min(this.i + o, this.toks.length - 1)]!;
  }

  private next(): Token {
    const t = this.peek();
    if (this.i < this.toks.length - 1) this.i++;
    return t;
  }

  private is(kind: Token["kind"], text?: string, o = 0): boolean {
    const t = this.peek(o);
    return t.kind === kind && (text === undefined || t.text === text);
  }

  private isWord(word: string, o = 0): boolean {
    return this.is("name", word, o);
  }

  private expect(kind: Token["kind"], text: string): Token {
    if (!this.is(kind, text)) {
      const t = this.peek();
      throw new FeelSyntaxError(`expected ${JSON.stringify(text)} but found ${t.kind === "eof" ? "the end" : JSON.stringify(t.text)}`, t.pos);
    }
    return this.next();
  }

  private enter(): void {
    this.depth += 1;
    if (this.depth > MAX_DEPTH) throw new FeelSyntaxError(`nested more than ${MAX_DEPTH} deep`, this.peek().pos, true);
  }

  private leave(): void {
    this.depth -= 1;
  }

  parseAll(): Node {
    const e = this.expr();
    if (!this.is("eof")) {
      const t = this.peek();
      throw new FeelSyntaxError(`unexpected ${JSON.stringify(t.text)}`, t.pos);
    }
    return e;
  }

  expr(): Node {
    this.enter();
    try {
      if ((this.isWord("some") || this.isWord("every")) && this.is("name", undefined, 1) && this.isWord("in", 2)) return this.quantified();
      return this.disjunction();
    } finally {
      this.leave();
    }
  }

  private quantified(): Node {
    const every = this.next().text === "every";
    const iters: { name: string; list: Node }[] = [];
    do {
      const name = this.next();
      if (name.kind !== "name" || KEYWORDS.has(name.text)) throw new FeelSyntaxError("a quantifier needs a variable name", name.pos);
      this.expect("name", "in");
      iters.push({ name: name.text, list: this.disjunction() });
    } while (this.is("punct", ",") && this.next());
    this.expect("name", "satisfies");
    return { k: "quant", every, iters, satisfies: this.expr() };
  }

  private disjunction(): Node {
    let l = this.conjunction();
    while (this.isWord("or")) {
      this.next();
      l = { k: "or", l, r: this.conjunction() };
    }
    return l;
  }

  private conjunction(): Node {
    let l = this.comparison();
    while (this.isWord("and")) {
      this.next();
      l = { k: "and", l, r: this.comparison() };
    }
    return l;
  }

  private comparison(): Node {
    const l = this.additive();
    const t = this.peek();
    if (t.kind === "op" && ["=", "!=", "<", "<=", ">", ">="].includes(t.text)) {
      this.next();
      return { k: "cmp", op: t.text as CmpOp, l, r: this.additive() };
    }
    if (this.isWord("between")) {
      this.next();
      const lo = this.additive();
      this.expect("name", "and");
      return { k: "between", e: l, lo, hi: this.additive() };
    }
    if (this.isWord("in")) {
      this.next();
      return { k: "in", e: l, tests: this.inTests() };
    }
    if (this.isWord("instance")) throw new FeelSyntaxError(REFUSED_WORDS.instance!, t.pos, true);
    return l;
  }

  /** After `in`: one test, or a parenthesised list of them. */
  private inTests(): Test[] {
    if (this.is("punct", "(")) {
      const open = this.next();
      if (this.isCmpStart()) {
        const tests = [this.cmpTest()];
        while (this.is("punct", ",") && this.next()) tests.push(this.test());
        this.expect("punct", ")");
        return tests;
      }
      const first = this.expr();
      if (this.is("punct", "..")) {
        this.next();
        const hi = this.additive();
        return [{ k: "interval", lo: first, hi, loClosed: false, hiClosed: this.closeInterval(open.pos) }];
      }
      const tests: Test[] = [{ k: "expr", e: first }];
      while (this.is("punct", ",") && this.next()) tests.push(this.test());
      this.expect("punct", ")");
      return tests;
    }
    return [this.test()];
  }

  private isCmpStart(): boolean {
    const t = this.peek();
    return t.kind === "op" && ["=", "!=", "<", "<=", ">", ">="].includes(t.text);
  }

  private cmpTest(): Test {
    const op = this.next().text as CmpOp;
    return { k: "cmp", op, e: this.additive() };
  }

  private closeInterval(pos: number): boolean {
    if (this.is("punct", "]")) {
      this.next();
      return true;
    }
    if (this.is("punct", ")") || this.is("punct", "[")) {
      this.next();
      return false;
    }
    throw new FeelSyntaxError("an interval ends with ] or ) or [", pos);
  }

  /** One positive unary test: a comparison, an interval, or an expression. */
  private test(): Test {
    if (this.isCmpStart()) return this.cmpTest();
    if (this.is("punct", "]")) {
      const open = this.next();
      const lo = this.additive();
      this.expect("punct", "..");
      const hi = this.additive();
      return { k: "interval", lo, hi, loClosed: false, hiClosed: this.closeInterval(open.pos) };
    }
    if (this.is("punct", "(") || this.is("punct", "[")) {
      const save = this.i;
      const open = this.next();
      if (!(open.text === "[" && this.is("punct", "]"))) {
        const lo = this.additive();
        if (this.is("punct", "..")) {
          this.next();
          const hi = this.additive();
          return { k: "interval", lo, hi, loClosed: open.text === "[", hiClosed: this.closeInterval(open.pos) };
        }
      }
      this.i = save;
    }
    return { k: "expr", e: this.additive() };
  }

  private additive(): Node {
    let l = this.multiplicative();
    while (this.is("op", "+") || this.is("op", "-")) {
      const op = this.next().text as ArithOp;
      l = { k: "arith", op, l, r: this.multiplicative() };
    }
    return l;
  }

  private multiplicative(): Node {
    let l = this.unary();
    while (this.is("op", "*") || this.is("op", "/")) {
      const op = this.next().text as ArithOp;
      l = { k: "arith", op, l, r: this.unary() };
    }
    return l;
  }

  private unary(): Node {
    if (this.is("op", "-")) {
      this.next();
      this.enter();
      try {
        return { k: "neg", e: this.unary() };
      } finally {
        this.leave();
      }
    }
    return this.postfix();
  }

  private postfix(): Node {
    let n = this.primary();
    for (;;) {
      if (this.is("punct", ".")) {
        this.next();
        const name = this.next();
        if (name.kind !== "name") throw new FeelSyntaxError("a path needs a name after the dot", name.pos);
        n = { k: "path", target: n, name: name.text };
        continue;
      }
      if (this.is("punct", "[")) {
        this.next();
        const inner = this.expr();
        this.expect("punct", "]");
        const literal = inner.k === "num" ? inner.v : inner.k === "neg" && inner.e.k === "num" ? inner.e.v.neg() : null;
        n = literal !== null ? { k: "index", target: n, index: literal } : { k: "filter", target: n, test: inner };
        continue;
      }
      if (this.is("punct", "(")) {
        throw new FeelSyntaxError("only the subset's builtins can be called", this.peek().pos, true);
      }
      return n;
    }
  }

  private primary(): Node {
    const t = this.peek();
    switch (t.kind) {
      case "number":
        this.next();
        return { k: "num", v: Decimal.parse(t.text)! };
      case "string":
        this.next();
        return { k: "str", v: t.value! };
      case "at":
        this.next();
        checkAtLiteral(t.value!, t.pos);
        return { k: "at", text: t.value! };
      case "punct":
        if (t.text === "(") {
          this.next();
          const e = this.expr();
          if (this.is("punct", "..")) throw new FeelSyntaxError("ranges as values are not in the subset — use one inside `in`", this.peek().pos, true);
          this.expect("punct", ")");
          return e;
        }
        if (t.text === "[") return this.listLiteral();
        if (t.text === "]") throw new FeelSyntaxError("ranges as values are not in the subset — use one inside `in`", t.pos, true);
        break;
      case "name":
        return this.namePrimary();
      default:
        break;
    }
    throw new FeelSyntaxError(t.kind === "eof" ? "the expression ends too soon" : `unexpected ${JSON.stringify(t.text)}`, t.pos);
  }

  private listLiteral(): Node {
    const open = this.next();
    const items: Node[] = [];
    if (this.is("punct", "]")) {
      this.next();
      return { k: "list", items };
    }
    items.push(this.expr());
    if (this.is("punct", "..")) throw new FeelSyntaxError("ranges as values are not in the subset — use one inside `in`", open.pos, true);
    while (this.is("punct", ",") && this.next()) items.push(this.expr());
    this.expect("punct", "]");
    return { k: "list", items };
  }

  private namePrimary(): Node {
    const t = this.peek();
    // A quantifier may stand as an operand (`a and some x in l satisfies b`); its `satisfies` runs to the end, as in FEEL.
    if ((t.text === "some" || t.text === "every") && this.is("name", undefined, 1) && this.isWord("in", 2)) {
      this.enter();
      try {
        return this.quantified();
      } finally {
        this.leave();
      }
    }
    // The four builtins whose names have spaces (two of them contain `and`).
    for (const words of MULTIWORD) {
      if (words.every((w, j) => this.isWord(w, j)) && this.is("punct", "(", words.length)) {
        for (let j = 0; j < words.length; j++) this.next();
        return this.call(words.join(" ") as Builtin, t.pos);
      }
    }
    const refused = REFUSED_WORDS[t.text];
    if (refused !== undefined) throw new FeelSyntaxError(refused, t.pos, true);
    if (t.text === "true" || t.text === "false") {
      this.next();
      return { k: "bool", v: t.text === "true" };
    }
    if (t.text === "null") {
      this.next();
      return { k: "null" };
    }
    if (KEYWORDS.has(t.text) && t.text !== "not") throw new FeelSyntaxError(`unexpected ${JSON.stringify(t.text)}`, t.pos);
    // A run of names before "(" is a multi-word function FEEL has and the subset does not.
    let j = 0;
    const words: string[] = [];
    while (this.is("name", undefined, j) && !(KEYWORDS.has(this.peek(j).text) && j > 0)) {
      words.push(this.peek(j).text);
      j++;
    }
    const builtin = Object.prototype.hasOwnProperty.call(BUILTINS, t.text);
    if (this.is("punct", "(", j) && (j > 1 || !builtin)) {
      throw new FeelSyntaxError(`the function ${JSON.stringify(words.join(" "))} is not in the subset`, t.pos, true);
    }
    if (this.is("punct", "(", 1) && builtin) {
      this.next();
      return this.call(t.text as Builtin, t.pos);
    }
    if (t.text === "not") throw new FeelSyntaxError("not is a function: not(…)", t.pos);
    if (j > 1) throw new FeelSyntaxError(`names with spaces are not in the subset (${JSON.stringify(words.join(" "))})`, t.pos, true);
    this.next();
    return { k: "name", name: t.text, pos: t.pos };
  }

  private call(fn: Builtin, pos: number): Node {
    this.expect("punct", "(");
    const args: Node[] = [];
    let named: Record<string, Node> | null = null;
    if (!this.is("punct", ")")) {
      do {
        if (this.is("name") && this.is("punct", ":", 1)) {
          const n = this.next().text;
          this.next();
          named ??= {};
          if (n in named) throw new FeelSyntaxError(`the argument ${n} is named twice`, pos);
          named[n] = this.expr();
        } else {
          if (named !== null) throw new FeelSyntaxError("positional arguments cannot follow named ones", pos);
          args.push(this.expr());
        }
      } while (this.is("punct", ",") && this.next());
    }
    this.expect("punct", ")");
    if (named !== null && args.length > 0) throw new FeelSyntaxError("arguments are all named or all positional", pos);
    const sigs = BUILTINS[fn] as readonly (readonly string[] | "variadic")[];
    const fits =
      named === null
        ? (sigs.includes("variadic") && args.length >= 1) || sigs.some((s) => s !== "variadic" && s.length === args.length)
        : sigs.some((s) => s !== "variadic" && s.length === Object.keys(named!).length && s.every((p) => Object.prototype.hasOwnProperty.call(named, p)));
    if (!fits) throw new FeelSyntaxError(`${fn}(…) with these arguments is not in the subset`, pos, true);
    if (fn === "date and time") {
      const a = args[0] ?? named?.from;
      if (a?.k === "str" && !isZonedFreeDateTime(a.v)) {
        throw new FeelSyntaxError("a date and time in the subset carries an offset or Z — never local, never a zone id", pos, true);
      }
    }
    return { k: "call", fn, args, named };
  }
}

const TIME_RE = /^-?\d{2}:\d{2}:\d{2}/;
const DATE_ONLY_RE = /^-?\d{4,9}-\d{2}-\d{2}$/;

/** A date-time literal the subset can read: not local, not zoned, not date-only (which FEEL reads as local midnight). */
function isZonedFreeDateTime(text: string): boolean {
  return !LOCAL_OR_ZONED_DT_RE.test(text) && !DATE_ONLY_RE.test(text) && !/@/.test(text);
}

/** Refuse an @-literal outside the subset: a time, or a local or zoned date-time. A malformed one stays and reads as null. */
function checkAtLiteral(text: string, pos: number): void {
  if (TIME_RE.test(text)) throw new FeelSyntaxError("the `time` type is not in the subset", pos, true);
  if (LOCAL_OR_ZONED_DT_RE.test(text) || (/T/.test(text) && /@/.test(text))) {
    throw new FeelSyntaxError("a date and time in the subset carries an offset or Z — never local, never a zone id", pos, true);
  }
}

/** Parse a FEEL expression in the subset. Throws `FeelSyntaxError`. */
export function parseFeel(src: string): Node {
  if (new TextEncoder().encode(src).length > MAX_SOURCE_BYTES) {
    throw new FeelSyntaxError(`a condition is at most ${MAX_SOURCE_BYTES} bytes`, 0, true);
  }
  return new Parser(lex(src)).parseAll();
}
