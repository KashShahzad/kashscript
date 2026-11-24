/**
 * The scans the rules run over TypeScript sources. Each returns plain hits; `check.ts` turns them into findings.
 */

import {
  constInitializer,
  declarationOf,
  enclosingFunction,
  functionName,
  hasExport,
  importOrigin,
  isPriceValue,
  leaves,
  lineOf,
  originIsFloor,
  propName,
  ts,
  unwrapExpression,
  valueTree,
  type FloorCtx,
} from "./ts.js";

/* ── suppress, by import and call site ───────────────────────────────────── */

export interface SuppressHit {
  readonly kind: "not-floor" | "k" | "cast";
  readonly fn: string;
  readonly line: number;
  readonly detail: string;
}

function floorBinding(name: string, at: ts.Node, abs: string, floor: FloorCtx): string | undefined {
  const decl = declarationOf(name, at);
  if (decl === undefined) return undefined;
  const origin = importOrigin(decl);
  return origin !== undefined && originIsFloor(origin, abs, floor) ? origin.imported : undefined;
}

function kAcceptable(arg: ts.Expression | undefined, abs: string, floor: FloorCtx): boolean {
  if (arg === undefined) return true;
  const e = unwrapExpression(arg);
  if (ts.isNumericLiteral(e)) {
    const v = Number(e.text);
    return Number.isInteger(v) && v >= 5;
  }
  if (ts.isIdentifier(e)) return floorBinding(e.text, e, abs, floor) === "FLOOR_K";
  if (ts.isPropertyAccessExpression(e) && ts.isIdentifier(e.expression) && e.name.text === "FLOOR_K") {
    return floorBinding(e.expression.text, e.expression, abs, floor) === "*";
  }
  return false;
}

/**
 * Every call of `suppress` or `suppressSeries`: it must be the floor's (the import, not a copy, a renaming that
 * leads elsewhere, or a shadowing local), and its k must be a whole-number literal of at least 5 or the floor's
 * FLOOR_K. Every cast to FloorCount or FloorTotal is refused: a branded count comes only from `suppress`.
 * `runtimeFile` is set for the floor's own src/suppress.ts, which defines both.
 */
export function suppressHits(sf: ts.SourceFile, abs: string, floor: FloorCtx, runtimeFile: boolean): SuppressHit[] {
  const out: SuppressHit[] = [];
  const hit = (kind: SuppressHit["kind"], node: ts.Node, detail: string): void => {
    out.push({ kind, fn: enclosingFunction(node).name, line: lineOf(node), detail });
  };
  const checkArgs = (call: ts.CallExpression, which: string): void => {
    if (which === "suppress") {
      if (!kAcceptable(call.arguments[1], abs, floor)) hit("k", call, `suppress(…, ${call.arguments[1]?.getText() ?? ""})`);
    } else if (which === "suppressSeries") {
      const opts = call.arguments[1];
      if (opts === undefined) return;
      const o = unwrapExpression(opts);
      if (!ts.isObjectLiteralExpression(o)) {
        hit("k", call, "suppressSeries' options are not written in the call, so its k cannot be read");
        return;
      }
      for (const p of o.properties) {
        if (ts.isPropertyAssignment(p) && propName(p.name) === "k" && !kAcceptable(p.initializer, abs, floor)) hit("k", call, `suppressSeries(…, { k: ${p.initializer.getText()} })`);
        if (ts.isShorthandPropertyAssignment(p) && p.name.text === "k") hit("k", call, "suppressSeries(…, { k })");
      }
    }
  };
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const callee = node.expression;
      if (ts.isIdentifier(callee)) {
        const decl = declarationOf(callee.text, callee);
        const origin = decl === undefined ? undefined : importOrigin(decl);
        if (origin !== undefined && originIsFloor(origin, abs, floor)) {
          if (origin.imported === "suppress" || origin.imported === "suppressSeries") checkArgs(node, origin.imported);
        } else if (callee.text === "suppress" || callee.text === "suppressSeries") {
          // The runtime file defines both and passes its caller's k through; suppress checks k when it runs.
          const ownDefinition = runtimeFile && decl !== undefined && ts.isFunctionDeclaration(decl);
          if (!ownDefinition) {
            const where = decl === undefined ? "nowhere in this file" : origin !== undefined ? `imported from "${origin.module}"` : `declared here, on line ${lineOf(decl)}`;
            hit("not-floor", node, `calls a ${callee.text} that is not the floor's (${where})`);
          }
        }
      } else if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression)) {
        const which = callee.name.text;
        if ((which === "suppress" || which === "suppressSeries") && floorBinding(callee.expression.text, callee.expression, abs, floor) === "*") checkArgs(node, which);
      }
    }
    if ((ts.isAsExpression(node) || ts.isTypeAssertionExpression(node)) && !runtimeFile) {
      const t = node.type;
      if (ts.isTypeReferenceNode(t)) {
        const tn = t.typeName;
        let floorType: string | undefined;
        if (ts.isIdentifier(tn)) {
          const imported = floorBinding(tn.text, t, abs, floor);
          if (imported === "FloorCount" || imported === "FloorTotal") floorType = imported;
        } else if (ts.isIdentifier(tn.left) && (tn.right.text === "FloorCount" || tn.right.text === "FloorTotal") && floorBinding(tn.left.text, t, abs, floor) === "*") {
          floorType = tn.right.text;
        }
        if (floorType !== undefined) hit("cast", node, `casts to ${floorType}: a count passes suppress, never a cast`);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

/* ── count sites ─────────────────────────────────────────────────────────── */

export interface CountSite {
  readonly fn: string;
  readonly fnNode: ts.Node | undefined;
  readonly line: number;
  readonly what: string;
}

const SQL_COUNT = /\b(count|sum)\s*\(\s*(?:\*|distinct\b|[A-Za-z_"][\w."]*\s*\))/i;

/** Where a count is computed: `.count()`, `.aggregate()`, `.groupBy()`, `count()`, `_count`, a count or sum in SQL text. */
export function countSites(sf: ts.SourceFile): CountSite[] {
  const out: CountSite[] = [];
  const add = (node: ts.Node, what: string): void => {
    const fn = enclosingFunction(node);
    out.push({ fn: fn.name, fnNode: fn.node, line: lineOf(node), what });
  };
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const c = node.expression;
      if (ts.isPropertyAccessExpression(c) && ["count", "aggregate", "groupBy"].includes(c.name.text)) add(node, `.${c.name.text}()`);
      else if (ts.isIdentifier(c) && c.text === "count") add(node, "count()");
    } else if ((ts.isPropertyAssignment(node) || ts.isShorthandPropertyAssignment(node)) && ["_count", "_sum", "_avg"].includes(propName(node.name) ?? "")) {
      add(node, propName(node.name) ?? "_count");
    } else if (
      ts.isPropertyAssignment(node) &&
      propName(node.name) === "count" &&
      ts.isStringLiteral(node.initializer) &&
      ["exact", "planned", "estimated"].includes(node.initializer.text)
    ) {
      add(node, `Supabase's count: "${node.initializer.text}"`);
    } else if (ts.isPropertyAccessExpression(node) && ["_count", "_sum", "_avg"].includes(node.name.text)) {
      add(node, node.name.text);
    } else if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      if (SQL_COUNT.test(node.text)) add(node, "a count in SQL");
    } else if (ts.isTemplateExpression(node)) {
      const text = node.head.text + node.templateSpans.map((s) => ` ${s.literal.text}`).join("");
      if (SQL_COUNT.test(text)) add(node, "a count in SQL");
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

/** Casts to any or unknown inside a function: a raw count can hide behind them past the declared type. */
export function escapeCasts(fn: ts.Node): number[] {
  const lines: number[] = [];
  const visit = (node: ts.Node): void => {
    if ((ts.isAsExpression(node) || ts.isTypeAssertionExpression(node)) && (node.type.kind === ts.SyntaxKind.AnyKeyword || node.type.kind === ts.SyntaxKind.UnknownKeyword)) {
      lines.push(lineOf(node));
    }
    ts.forEachChild(node, visit);
  };
  visit(fn);
  return lines;
}

/* ── the aggregate's function ────────────────────────────────────────────── */

export interface ExportedFunction {
  readonly node: ts.Node;
  readonly returnType: ts.TypeNode | undefined;
}

export function exportedFunction(sf: ts.SourceFile, name: string): ExportedFunction | undefined {
  const fromLocal = (local: string): ExportedFunction | undefined => {
    for (const s of sf.statements) {
      if (ts.isFunctionDeclaration(s) && s.name?.text === local) return { node: s, returnType: s.type };
      if (ts.isVariableStatement(s)) {
        for (const d of s.declarationList.declarations) {
          if (!ts.isIdentifier(d.name) || d.name.text !== local || d.initializer === undefined) continue;
          const init = unwrapExpression(d.initializer);
          if (ts.isArrowFunction(init) || ts.isFunctionExpression(init)) {
            const annotated = d.type !== undefined && ts.isFunctionTypeNode(d.type) ? d.type.type : undefined;
            return { node: init, returnType: init.type ?? annotated };
          }
        }
      }
    }
    return undefined;
  };
  for (const s of sf.statements) {
    if (ts.isFunctionDeclaration(s) && s.name?.text === name && hasExport(s)) return { node: s, returnType: s.type };
    if (ts.isVariableStatement(s) && hasExport(s)) {
      for (const d of s.declarationList.declarations) if (ts.isIdentifier(d.name) && d.name.text === name) return fromLocal(name);
    }
    if (ts.isExportDeclaration(s) && s.moduleSpecifier === undefined && s.exportClause !== undefined && ts.isNamedExports(s.exportClause)) {
      for (const el of s.exportClause.elements) if (el.name.text === name) return fromLocal((el.propertyName ?? el.name).text);
    }
  }
  return undefined;
}

/* ── lexicons written in the DSL ─────────────────────────────────────────── */

export interface DslObject {
  /** The variable the schema is assigned to, and the properties down to this object. */
  readonly path: string;
  readonly props: ReadonlyMap<string, ts.Expression>;
  readonly required: readonly string[];
  readonly line: number;
}

/** Every `S.object({ … }, [required])` in a file — the lexicons package's schema language. */
export function dslObjects(sf: ts.SourceFile): DslObject[] {
  const out: DslObject[] = [];
  const labelOf = (call: ts.Node): string => {
    const parts: string[] = [];
    let n: ts.Node | undefined = call.parent;
    while (n !== undefined && !ts.isSourceFile(n)) {
      if (ts.isPropertyAssignment(n)) {
        const p = propName(n.name);
        if (p !== undefined) parts.unshift(p);
      } else if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name)) {
        parts.unshift(n.name.text);
        break;
      }
      n = n.parent;
    }
    return parts.join(".");
  };
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && ts.isIdentifier(node.expression.expression) && node.expression.expression.text === "S" && node.expression.name.text === "object") {
      const first = node.arguments[0];
      if (first !== undefined && ts.isObjectLiteralExpression(first)) {
        const props = new Map<string, ts.Expression>();
        for (const p of first.properties) {
          if (ts.isPropertyAssignment(p)) {
            const name = propName(p.name);
            if (name !== undefined) props.set(name, p.initializer);
          }
        }
        const req = node.arguments[1];
        const required = req !== undefined && ts.isArrayLiteralExpression(req) ? req.elements.filter(ts.isStringLiteral).map((e) => e.text) : [];
        out.push({ path: labelOf(node), props, required, line: lineOf(node) });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

/* ── routes, actions and tables ──────────────────────────────────────────── */

const HTTP = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);

/** The HTTP methods a Next route file exports. */
export function routeMethods(sf: ts.SourceFile): string[] {
  const out = new Set<string>();
  for (const s of sf.statements) {
    if (ts.isFunctionDeclaration(s) && hasExport(s) && s.name !== undefined && HTTP.has(s.name.text)) out.add(s.name.text);
    if (ts.isVariableStatement(s) && hasExport(s)) {
      for (const d of s.declarationList.declarations) if (ts.isIdentifier(d.name) && HTTP.has(d.name.text)) out.add(d.name.text);
    }
    if (ts.isExportDeclaration(s) && s.exportClause !== undefined && ts.isNamedExports(s.exportClause)) {
      for (const el of s.exportClause.elements) if (HTTP.has(el.name.text)) out.add(el.name.text);
    }
  }
  return [...out].sort();
}

function directive(stmts: readonly ts.Statement[], text: string): boolean {
  for (const s of stmts) {
    if (!ts.isExpressionStatement(s) || !ts.isStringLiteral(s.expression)) return false;
    if (s.expression.text === text) return true;
  }
  return false;
}

/** Server actions: every export of a `"use server"` file, and every function whose body begins with the directive. */
export function serverActions(sf: ts.SourceFile): string[] {
  const out = new Set<string>();
  if (directive(sf.statements, "use server")) {
    for (const s of sf.statements) {
      if (ts.isFunctionDeclaration(s) && hasExport(s)) out.add(s.name?.text ?? "default");
      if (ts.isVariableStatement(s) && hasExport(s)) for (const d of s.declarationList.declarations) if (ts.isIdentifier(d.name)) out.add(d.name.text);
      if (ts.isExportDeclaration(s) && s.exportClause !== undefined && ts.isNamedExports(s.exportClause)) for (const el of s.exportClause.elements) out.add(el.name.text);
      if (ts.isExportAssignment(s)) out.add("default");
    }
  }
  const visit = (node: ts.Node): void => {
    if (
      (ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node) || ts.isMethodDeclaration(node)) &&
      node.body !== undefined &&
      ts.isBlock(node.body) &&
      directive(node.body.statements, "use server")
    ) {
      out.add(functionName(node) ?? `line${lineOf(node)}`);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return [...out].sort();
}

export interface TableEntry {
  readonly name: string | undefined;
  readonly method: string | undefined;
  readonly path: string | undefined;
  readonly mapKey: string | undefined;
  readonly line: number;
}

/** The entries of an exported table (an array or an object literal), each read through wrapper calls such as def({…}). */
export function tableEntries(sf: ts.SourceFile, exportName: string, key: string): { entries: TableEntry[] } | { error: string } {
  const init = constInitializer(sf, exportName);
  if (init === undefined) return { error: `no exported const ${exportName}` };
  const table = unwrapExpression(init);
  const read = (value: ts.Expression, mapKey: string | undefined): TableEntry | string => {
    let v = unwrapExpression(value);
    if (ts.isIdentifier(v)) {
      const resolved = constInitializer(sf, v.text);
      if (resolved !== undefined) v = unwrapExpression(resolved);
    }
    if (ts.isCallExpression(v) && v.arguments[0] !== undefined) {
      const arg = unwrapExpression(v.arguments[0]);
      if (ts.isStringLiteral(arg)) return { name: arg.text, method: undefined, path: undefined, mapKey, line: lineOf(v) };
      v = arg;
    }
    if (!ts.isObjectLiteralExpression(v)) return mapKey === undefined ? `an entry on line ${lineOf(value)} the floor cannot read` : { name: undefined, method: undefined, path: undefined, mapKey, line: lineOf(value) };
    const str = (k: string): string | undefined => {
      for (const p of v.properties) {
        if (ts.isPropertyAssignment(p) && propName(p.name) === k) {
          const iv = unwrapExpression(p.initializer);
          if (ts.isStringLiteral(iv) || ts.isNoSubstitutionTemplateLiteral(iv)) return iv.text;
        }
      }
      return undefined;
    };
    return { name: str(key), method: str("method"), path: str("path"), mapKey, line: lineOf(v) };
  };
  const entries: TableEntry[] = [];
  if (ts.isArrayLiteralExpression(table)) {
    for (const el of table.elements) {
      if (ts.isSpreadElement(el)) return { error: `a spread on line ${lineOf(el)} the floor cannot read` };
      const e = read(el, undefined);
      if (typeof e === "string") return { error: e };
      entries.push(e);
    }
  } else if (ts.isObjectLiteralExpression(table)) {
    for (const p of table.properties) {
      if (!ts.isPropertyAssignment(p)) return { error: `a member on line ${lineOf(p)} the floor cannot read` };
      const e = read(p.initializer, propName(p.name));
      if (typeof e === "string") return { error: e };
      entries.push(e);
    }
  } else {
    return { error: `${exportName} is neither an array nor an object literal` };
  }
  return { entries };
}

/* ── text and names, for prices ──────────────────────────────────────────── */

/** String literals, template text and JSX text: where a price figure written in copy would be. */
export function copyTexts(sf: ts.SourceFile): Array<{ readonly text: string; readonly line: number }> {
  const out: Array<{ text: string; line: number }> = [];
  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node) || ts.isLiteralTypeNode(node)) return;
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) out.push({ text: node.text, line: lineOf(node) });
    else if (ts.isTemplateExpression(node)) {
      out.push({ text: node.head.text, line: lineOf(node) });
      for (const s of node.templateSpans) out.push({ text: s.literal.text, line: lineOf(s) });
    } else if (ts.isJsxText(node)) out.push({ text: node.text, line: lineOf(node) });
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

export function exportedConsts(sf: ts.SourceFile): Array<{ readonly name: string; readonly init: ts.Expression; readonly line: number }> {
  const out: Array<{ name: string; init: ts.Expression; line: number }> = [];
  for (const s of sf.statements) {
    if (!ts.isVariableStatement(s) || !hasExport(s)) continue;
    for (const d of s.declarationList.declarations) if (ts.isIdentifier(d.name) && d.initializer !== undefined) out.push({ name: d.name.text, init: d.initializer, line: lineOf(d) });
  }
  return out;
}

/** Does a value hold a price: a number, a decimal string, or an object literal with one inside? */
function priceLikeValue(e: ts.Expression | undefined, sf: ts.SourceFile): boolean {
  if (e === undefined) return false;
  return leaves(valueTree(e, sf)).some(isPriceValue);
}

/**
 * Is a member typed as a price could be: a number, or a named type (Money, Amount …)? A string is copy text here; a
 * price written as a decimal string lives in a price file, which is read field by field.
 */
function priceLikeType(t: ts.TypeNode | undefined): boolean {
  if (t === undefined) return false;
  if (ts.isUnionTypeNode(t)) return t.types.some((x) => priceLikeType(x));
  if (ts.isParenthesizedTypeNode(t)) return priceLikeType(t.type);
  return t.kind === ts.SyntaxKind.NumberKeyword || t.kind === ts.SyntaxKind.BigIntKeyword || ts.isTypeReferenceNode(t);
}

/**
 * Every member name, with the name of what holds it: interface and type members, object literal keys, class fields,
 * consts. `priceLike` says whether it can hold a price — a number, a decimal string, or a type that may be one — so a
 * key such as "price-per-record" naming a rule is not read as a price.
 */
export function memberNames(sf: ts.SourceFile): Array<{ readonly container: string; readonly member: string; readonly line: number; readonly priceLike: boolean }> {
  const out: Array<{ container: string; member: string; line: number; priceLike: boolean }> = [];
  const holder = (node: ts.Node): string => {
    let n: ts.Node | undefined = node.parent;
    while (n !== undefined && !ts.isSourceFile(n)) {
      if (ts.isInterfaceDeclaration(n) || ts.isTypeAliasDeclaration(n) || ts.isClassDeclaration(n)) return n.name?.text ?? "";
      if (ts.isPropertyAssignment(n) || ts.isPropertySignature(n)) return propName(n.name) ?? "";
      if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name)) return n.name.text;
      n = n.parent;
    }
    return "";
  };
  const visit = (node: ts.Node): void => {
    if (ts.isPropertySignature(node)) {
      const name = propName(node.name);
      if (name !== undefined) out.push({ container: holder(node), member: name, line: lineOf(node), priceLike: priceLikeType(node.type) });
    } else if (ts.isPropertyAssignment(node)) {
      const name = propName(node.name);
      if (name !== undefined) out.push({ container: holder(node), member: name, line: lineOf(node), priceLike: priceLikeValue(node.initializer, sf) });
    } else if (ts.isPropertyDeclaration(node)) {
      const name = propName(node.name);
      if (name !== undefined) out.push({ container: holder(node), member: name, line: lineOf(node), priceLike: node.initializer !== undefined ? priceLikeValue(node.initializer, sf) : priceLikeType(node.type) });
    } else if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name)) {
      out.push({ container: "", member: node.name.text, line: lineOf(node), priceLike: priceLikeValue(node.initializer, sf) });
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}
