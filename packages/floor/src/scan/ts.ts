/**
 * The TypeScript side of the scanner: syntax only, never the type checker (the repositories' own `tsc` does that).
 * Files are parsed once and cached; names are resolved through scopes; types are expanded into trees through the
 * file's own declarations and its relative imports; values are read from literals.
 */

import ts from "typescript";
import { existsSync, readFileSync } from "node:fs";
import { dirname, relative, resolve, sep } from "node:path";

export { ts };

export function scriptKind(file: string): ts.ScriptKind {
  if (file.endsWith(".tsx")) return ts.ScriptKind.TSX;
  if (file.endsWith(".jsx")) return ts.ScriptKind.JSX;
  if (/\.(js|mjs|cjs)$/.test(file)) return ts.ScriptKind.JS;
  return ts.ScriptKind.TS;
}

export function parse(file: string, text: string): ts.SourceFile {
  return ts.createSourceFile(file, text.replace(/^﻿/, ""), ts.ScriptTarget.Latest, true, scriptKind(file));
}

export const isTsFile = (f: string): boolean => /\.(ts|tsx|mts|cts|js|jsx|mjs|cjs)$/.test(f) && !f.endsWith(".d.ts");

/** Parsed files by absolute path. */
export class Sources {
  private readonly cache = new Map<string, ts.SourceFile | null>();
  constructor(readonly root: string) {}

  get(abs: string): ts.SourceFile | undefined {
    const hit = this.cache.get(abs);
    if (hit !== undefined) return hit ?? undefined;
    let sf: ts.SourceFile | null = null;
    try {
      sf = parse(abs, readFileSync(abs, "utf8"));
    } catch {
      sf = null;
    }
    this.cache.set(abs, sf);
    return sf ?? undefined;
  }

  /** Seed a file from memory (the self-test's cases are never written to disk). */
  put(abs: string, text: string): ts.SourceFile {
    const sf = parse(abs, text);
    this.cache.set(abs, sf);
    return sf;
  }

  rel(abs: string): string {
    return relative(this.root, abs).split(sep).join("/");
  }
}

export function lineOf(node: ts.Node): number {
  const sf = node.getSourceFile();
  return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
}

/** A relative module specifier, resolved to a file that exists. */
export function resolveModule(fromAbs: string, spec: string): string | undefined {
  if (!spec.startsWith(".")) return undefined;
  const base = resolve(dirname(fromAbs), spec);
  const swapped = base.replace(/\.js$/, ".ts").replace(/\.jsx$/, ".tsx").replace(/\.mjs$/, ".mts").replace(/\.cjs$/, ".cts");
  const candidates = [
    base,
    swapped,
    base.replace(/\.js$/, ".tsx"),
    `${base}.ts`,
    `${base}.tsx`,
    `${base}.mts`,
    `${base}.d.ts`,
    `${base}.js`,
    `${base}/index.ts`,
    `${base}/index.tsx`,
  ];
  for (const c of candidates) if (/\.[cm]?[jt]sx?$/.test(c) && existsSync(c)) return c;
  return undefined;
}

/* ── names ────────────────────────────────────────────────────────────────── */

function bindsName(b: ts.BindingName, name: string): boolean {
  if (ts.isIdentifier(b)) return b.text === name;
  for (const el of b.elements) {
    if (ts.isOmittedExpression(el)) continue;
    if (bindsName(el.name, name)) return true;
  }
  return false;
}

function declaredIn(scope: ts.Node, name: string): ts.Node | undefined {
  if (ts.isFunctionLike(scope)) {
    for (const p of scope.parameters) if (bindsName(p.name, name)) return p;
    if (ts.isFunctionExpression(scope) && scope.name?.text === name) return scope;
  }
  if (ts.isCatchClause(scope) && scope.variableDeclaration !== undefined && bindsName(scope.variableDeclaration.name, name)) {
    return scope.variableDeclaration;
  }
  if ((ts.isForStatement(scope) || ts.isForInStatement(scope) || ts.isForOfStatement(scope)) && scope.initializer !== undefined && ts.isVariableDeclarationList(scope.initializer)) {
    for (const d of scope.initializer.declarations) if (bindsName(d.name, name)) return d;
  }
  let stmts: readonly ts.Statement[] | undefined;
  if (ts.isSourceFile(scope) || ts.isBlock(scope) || ts.isModuleBlock(scope) || ts.isCaseClause(scope) || ts.isDefaultClause(scope)) stmts = scope.statements;
  if (stmts === undefined) return undefined;
  for (const s of stmts) {
    if (ts.isVariableStatement(s)) {
      for (const d of s.declarationList.declarations) if (bindsName(d.name, name)) return d;
    } else if ((ts.isFunctionDeclaration(s) || ts.isClassDeclaration(s) || ts.isEnumDeclaration(s)) && s.name?.text === name) {
      return s;
    } else if (ts.isImportDeclaration(s) && s.importClause !== undefined) {
      const c = s.importClause;
      if (c.name?.text === name) return c;
      const nb = c.namedBindings;
      if (nb !== undefined && ts.isNamespaceImport(nb) && nb.name.text === name) return nb;
      if (nb !== undefined && ts.isNamedImports(nb)) for (const el of nb.elements) if (el.name.text === name) return el;
    } else if (ts.isImportEqualsDeclaration(s) && s.name.text === name) {
      return s;
    }
  }
  return undefined;
}

/** The nearest declaration of `name` visible from `from`, walking out through the scopes. */
export function declarationOf(name: string, from: ts.Node): ts.Node | undefined {
  let node: ts.Node | undefined = from.parent;
  while (node !== undefined) {
    const found = declaredIn(node, name);
    if (found !== undefined) return found;
    node = node.parent;
  }
  return undefined;
}

/** Where an import declaration's binding comes from: the module and the name imported (`*` for a namespace). */
export function importOrigin(decl: ts.Node): { module: string; imported: string } | undefined {
  if (ts.isImportSpecifier(decl)) {
    const imp = decl.parent.parent.parent;
    if (ts.isStringLiteral(imp.moduleSpecifier)) return { module: imp.moduleSpecifier.text, imported: (decl.propertyName ?? decl.name).text };
  } else if (ts.isNamespaceImport(decl)) {
    const imp = decl.parent.parent;
    if (ts.isStringLiteral(imp.moduleSpecifier)) return { module: imp.moduleSpecifier.text, imported: "*" };
  } else if (ts.isImportClause(decl)) {
    const imp = decl.parent;
    if (ts.isStringLiteral(imp.moduleSpecifier)) return { module: imp.moduleSpecifier.text, imported: "default" };
  }
  return undefined;
}

export const isFloorModule = (spec: string): boolean => spec === "@kashscript/floor" || spec.startsWith("@kashscript/floor/");

/**
 * How a file reaches the floor. `self` is set when the scanned repository is the floor itself and the file sits in its
 * own `src/`: there the runtime is imported by a relative path.
 */
export interface FloorCtx {
  readonly self: boolean;
}

export function originIsFloor(origin: { module: string } | undefined, fromAbs: string, ctx: FloorCtx): boolean {
  if (origin === undefined) return false;
  if (isFloorModule(origin.module)) return true;
  if (!ctx.self || !origin.module.startsWith(".")) return false;
  const target = resolveModule(fromAbs, origin.module);
  return target !== undefined && /[\\/]src[\\/](suppress|index)\.ts$/.test(target);
}

/** The name a function-like node is known by: its own name, or the variable or property it is assigned to. */
export function functionName(node: ts.Node): string | undefined {
  if ((ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node) || ts.isFunctionExpression(node)) && node.name !== undefined && ts.isIdentifier(node.name)) return node.name.text;
  if (ts.isMethodDeclaration(node) && node.name !== undefined && ts.isStringLiteral(node.name)) return node.name.text;
  const p = node.parent;
  if (p !== undefined && ts.isVariableDeclaration(p) && ts.isIdentifier(p.name)) return p.name.text;
  if (p !== undefined && ts.isPropertyAssignment(p) && (ts.isIdentifier(p.name) || ts.isStringLiteral(p.name))) return p.name.text;
  return undefined;
}

/** The nearest enclosing named function of a node, or `<module>`. */
export function enclosingFunction(node: ts.Node): { name: string; node: ts.Node | undefined } {
  let n: ts.Node | undefined = node.parent;
  while (n !== undefined) {
    if (ts.isFunctionLike(n)) {
      const name = functionName(n);
      if (name !== undefined) return { name, node: n };
    }
    n = n.parent;
  }
  return { name: "<module>", node: undefined };
}

export function isWithin(node: ts.Node, outer: ts.Node): boolean {
  let n: ts.Node | undefined = node;
  while (n !== undefined) {
    if (n === outer) return true;
    n = n.parent;
  }
  return false;
}

export function hasExport(node: ts.Node): boolean {
  return ts.canHaveModifiers(node) && (ts.getModifiers(node) ?? []).some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
}

export function unwrapExpression(e: ts.Expression): ts.Expression {
  let x = e;
  for (;;) {
    if (ts.isParenthesizedExpression(x) || ts.isAsExpression(x) || ts.isSatisfiesExpression(x) || ts.isTypeAssertionExpression(x) || ts.isNonNullExpression(x)) {
      x = x.expression;
    } else return x;
  }
}

/** A top-level `const NAME = …` initializer in a file. */
export function constInitializer(sf: ts.SourceFile, name: string): ts.Expression | undefined {
  for (const s of sf.statements) {
    if (!ts.isVariableStatement(s)) continue;
    for (const d of s.declarationList.declarations) if (ts.isIdentifier(d.name) && d.name.text === name && d.initializer !== undefined) return d.initializer;
  }
  return undefined;
}

export function propName(name: ts.PropertyName | ts.BindingName | undefined): string | undefined {
  if (name === undefined) return undefined;
  if (ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name) || ts.isPrivateIdentifier(name)) return name.text;
  if (ts.isComputedPropertyName(name) && ts.isStringLiteralLike(name.expression)) return name.expression.text;
  return undefined;
}

/* ── trees ───────────────────────────────────────────────────────────────── */

/**
 * Leaf classes. For types: `number`, `bigint`, `any`, `unknown`, `unresolved` (a type the floor cannot see), `floor`
 * (the floor's FloorCount or FloorTotal), `ok` (strings, booleans, literals, dates), `nullish`. For values: `num`,
 * `str`, `lit` (true, false, null), `computed` (anything not a literal).
 */
export type LeafClass = "ok" | "number" | "bigint" | "any" | "unknown" | "unresolved" | "floor" | "nullish" | "num" | "str" | "lit" | "computed";

export type Tree =
  | { readonly kind: "object"; readonly members: Map<string, Tree> }
  | { readonly kind: "array"; readonly element: Tree }
  | { readonly kind: "map"; readonly value: Tree }
  | { readonly kind: "leaf"; readonly cls: LeafClass; readonly text: string };

const RANK: Readonly<Record<LeafClass, number>> = {
  nullish: 0, floor: 1, ok: 1, num: 1, str: 1, lit: 1, computed: 2, number: 3, bigint: 3, unresolved: 4, unknown: 5, any: 6,
};

export const leaf = (cls: LeafClass, text: string): Tree => ({ kind: "leaf", cls, text });

function worst(t: Tree): LeafClass {
  if (t.kind === "leaf") return t.cls;
  if (t.kind === "array") return worst(t.element);
  if (t.kind === "map") return worst(t.value);
  let w: LeafClass = "nullish";
  for (const m of t.members.values()) {
    const c = worst(m);
    if (RANK[c] > RANK[w]) w = c;
  }
  return w;
}

export function mergeTrees(a: Tree, b: Tree): Tree {
  if (a.kind === "leaf" && a.cls === "nullish") return b;
  if (b.kind === "leaf" && b.cls === "nullish") return a;
  if (a.kind === "object" && b.kind === "object") {
    const members = new Map(a.members);
    for (const [k, v] of b.members) {
      const prior = members.get(k);
      members.set(k, prior === undefined ? v : mergeTrees(prior, v));
    }
    return { kind: "object", members };
  }
  if (a.kind === "array" && b.kind === "array") return { kind: "array", element: mergeTrees(a.element, b.element) };
  if (a.kind === "map" && b.kind === "map") return { kind: "map", value: mergeTrees(a.value, b.value) };
  if (a.kind === "leaf" && b.kind === "leaf") {
    const cls = RANK[a.cls] >= RANK[b.cls] ? a.cls : b.cls;
    return leaf(cls, a.text === b.text ? a.text : `${a.text} | ${b.text}`);
  }
  const wa = worst(a);
  const wb = worst(b);
  return leaf(RANK[wa] >= RANK[wb] ? wa : wb, "a union of shapes");
}

const join = (path: string, name: string): string => (path === "" ? name : `${path}.${name}`);

export interface LeafAt {
  readonly path: string;
  readonly cls: LeafClass;
  readonly text: string;
  /** The last named segment (a member name), if any. */
  readonly name: string | undefined;
  readonly inList: boolean;
}

export function leaves(t: Tree, path = "", name: string | undefined = undefined, inList = false): LeafAt[] {
  if (t.kind === "leaf") return [{ path, cls: t.cls, text: t.text, name, inList }];
  if (t.kind === "array") return leaves(t.element, path === "" ? "[]" : `${path}[]`, name, true);
  if (t.kind === "map") return leaves(t.value, join(path, "*"), name, inList);
  return [...t.members].flatMap(([k, v]) => leaves(v, join(path, k), k, inList));
}

export interface ObjectAt {
  readonly path: string;
  /** Direct members that are leaves, by name. */
  readonly leafMembers: ReadonlyArray<{ readonly name: string; readonly path: string }>;
}

export function objects(t: Tree, path = ""): ObjectAt[] {
  if (t.kind === "leaf") return [];
  if (t.kind === "array") return objects(t.element, path === "" ? "[]" : `${path}[]`);
  if (t.kind === "map") return objects(t.value, join(path, "*"));
  const here: ObjectAt = {
    path,
    leafMembers: [...t.members].filter(([, v]) => v.kind === "leaf").map(([k]) => ({ name: k, path: join(path, k) })),
  };
  return [here, ...[...t.members].flatMap(([k, v]) => objects(v, join(path, k)))];
}

/* ── types to trees ──────────────────────────────────────────────────────── */

export interface TypeCtx {
  readonly sources: Sources;
  readonly floor: FloorCtx;
  readonly seen: Set<string>;
}

function typeDeclIn(sf: ts.SourceFile, name: string): ts.InterfaceDeclaration | ts.TypeAliasDeclaration | undefined {
  for (const s of sf.statements) {
    if ((ts.isInterfaceDeclaration(s) || ts.isTypeAliasDeclaration(s)) && s.name.text === name) return s;
  }
  return undefined;
}

/** An exported type of a file, following `export { … } from` and `export * from`. */
function exportedTypeDecl(ctx: TypeCtx, abs: string, name: string, depth: number): { decl: ts.InterfaceDeclaration | ts.TypeAliasDeclaration; abs: string } | undefined {
  if (depth > 8) return undefined;
  const sf = ctx.sources.get(abs);
  if (sf === undefined) return undefined;
  const local = typeDeclIn(sf, name);
  if (local !== undefined) return { decl: local, abs };
  for (const s of sf.statements) {
    if (!ts.isExportDeclaration(s)) continue;
    const spec = s.moduleSpecifier !== undefined && ts.isStringLiteral(s.moduleSpecifier) ? s.moduleSpecifier.text : undefined;
    if (s.exportClause === undefined) {
      if (spec === undefined) continue;
      const target = resolveModule(abs, spec);
      const found = target === undefined ? undefined : exportedTypeDecl(ctx, target, name, depth + 1);
      if (found !== undefined) return found;
    } else if (ts.isNamedExports(s.exportClause)) {
      for (const el of s.exportClause.elements) {
        if (el.name.text !== name) continue;
        const inner = (el.propertyName ?? el.name).text;
        if (spec === undefined) {
          const d = typeDeclIn(sf, inner);
          if (d !== undefined) return { decl: d, abs };
        } else {
          const target = resolveModule(abs, spec);
          if (target !== undefined) return exportedTypeDecl(ctx, target, inner, depth + 1);
        }
      }
    }
  }
  return undefined;
}

/** An interface's or type alias's tree, with heritage and in-file and relative references followed. */
export function declTree(decl: ts.InterfaceDeclaration | ts.TypeAliasDeclaration, abs: string, ctx: TypeCtx): Tree {
  return expandDecl(decl, abs, ctx);
}

function expandDecl(decl: ts.InterfaceDeclaration | ts.TypeAliasDeclaration, abs: string, ctx: TypeCtx): Tree {
  const id = `${abs}#${decl.name.text}`;
  if (ctx.seen.has(id)) return leaf("unresolved", `${decl.name.text} (recursive)`);
  ctx.seen.add(id);
  try {
    if (ts.isTypeAliasDeclaration(decl)) return typeTree(decl.type, abs, ctx);
    let tree: Tree = membersTree(decl.members, abs, ctx);
    for (const h of decl.heritageClauses ?? []) {
      for (const t of h.types) {
        if (ts.isIdentifier(t.expression)) tree = mergeTrees(tree, referenceTree(t.expression.text, t.typeArguments, t, abs, ctx));
      }
    }
    return tree;
  } finally {
    ctx.seen.delete(id);
  }
}

function membersTree(members: ts.NodeArray<ts.TypeElement>, abs: string, ctx: TypeCtx): Tree {
  const out = new Map<string, Tree>();
  let index: Tree | undefined;
  for (const m of members) {
    if (ts.isPropertySignature(m)) {
      const name = propName(m.name);
      if (name === undefined) continue;
      out.set(name, m.type === undefined ? leaf("any", "untyped") : typeTree(m.type, abs, ctx));
    } else if (ts.isIndexSignatureDeclaration(m) && m.type !== undefined) {
      index = typeTree(m.type, abs, ctx);
    }
  }
  if (index !== undefined && out.size === 0) return { kind: "map", value: index };
  if (index !== undefined) out.set("*", index);
  return { kind: "object", members: out };
}

const BUILTIN_OK = new Set(["Date", "RegExp", "URL", "Uint8Array", "ArrayBuffer", "Buffer", "Blob", "Error"]);

function referenceTree(name: string, args: ts.NodeArray<ts.TypeNode> | undefined, at: ts.Node, abs: string, ctx: TypeCtx): Tree {
  const arg = (i: number): Tree => {
    const a = args?.[i];
    return a === undefined ? leaf("unresolved", name) : typeTree(a, abs, ctx);
  };
  switch (name) {
    case "Promise":
    case "Awaited":
    case "Readonly":
    case "Partial":
    case "Required":
    case "NonNullable":
      return arg(0);
    case "Array":
    case "ReadonlyArray":
    case "Set":
    case "ReadonlySet":
      return { kind: "array", element: arg(0) };
    case "Record":
      return { kind: "map", value: arg(1) };
    case "Map":
    case "ReadonlyMap":
    case "WeakMap":
      return { kind: "map", value: arg(1) };
    case "Pick":
    case "Omit": {
      const base = arg(0);
      const keysNode = args?.[1];
      if (base.kind !== "object" || keysNode === undefined) return base;
      const keys = new Set<string>();
      const collect = (n: ts.TypeNode): void => {
        if (ts.isUnionTypeNode(n)) n.types.forEach(collect);
        else if (ts.isLiteralTypeNode(n) && ts.isStringLiteral(n.literal)) keys.add(n.literal.text);
      };
      collect(keysNode);
      const members = new Map([...base.members].filter(([k]) => (name === "Pick" ? keys.has(k) : !keys.has(k))));
      return { kind: "object", members };
    }
    default:
      break;
  }
  if (BUILTIN_OK.has(name)) return leaf("ok", name);
  const sf = ctx.sources.get(abs);
  if (sf === undefined) return leaf("unresolved", name);
  const decl = declarationOf(name, at);
  if (decl !== undefined) {
    const origin = importOrigin(decl);
    if (origin !== undefined) {
      if (originIsFloor(origin, abs, ctx.floor) && (origin.imported === "FloorCount" || origin.imported === "FloorTotal")) return leaf("floor", origin.imported);
      const target = resolveModule(abs, origin.module);
      if (target !== undefined) {
        const found = exportedTypeDecl(ctx, target, origin.imported, 0);
        if (found !== undefined) return expandDecl(found.decl, found.abs, ctx);
      }
      return leaf("unresolved", name);
    }
  }
  const local = typeDeclIn(sf, name);
  if (local !== undefined) return expandDecl(local, abs, ctx);
  if (ctx.floor.self && (name === "FloorCount" || name === "FloorTotal") && /[\\/]src[\\/]suppress\.ts$/.test(abs)) return leaf("floor", name);
  return leaf("unresolved", name);
}

export function typeTree(node: ts.TypeNode, abs: string, ctx: TypeCtx): Tree {
  if (ts.isParenthesizedTypeNode(node)) return typeTree(node.type, abs, ctx);
  if (ts.isTypeLiteralNode(node)) return membersTree(node.members, abs, ctx);
  if (ts.isUnionTypeNode(node) || ts.isIntersectionTypeNode(node)) {
    return node.types.map((t) => typeTree(t, abs, ctx)).reduce((a, b) => mergeTrees(a, b));
  }
  if (ts.isArrayTypeNode(node)) return { kind: "array", element: typeTree(node.elementType, abs, ctx) };
  if (ts.isTupleTypeNode(node)) {
    const els = node.elements.map((e) => typeTree(ts.isNamedTupleMember(e) ? e.type : e, abs, ctx));
    return { kind: "array", element: els.length === 0 ? leaf("nullish", "[]") : els.reduce((a, b) => mergeTrees(a, b)) };
  }
  if (ts.isTypeOperatorNode(node)) {
    if (node.operator === ts.SyntaxKind.ReadonlyKeyword) return typeTree(node.type, abs, ctx);
    return leaf("ok", node.getText());
  }
  if (ts.isLiteralTypeNode(node)) {
    if (node.literal.kind === ts.SyntaxKind.NullKeyword) return leaf("nullish", "null");
    return leaf("ok", node.getText());
  }
  if (ts.isTemplateLiteralTypeNode(node) || ts.isFunctionTypeNode(node) || ts.isConstructorTypeNode(node)) return leaf("ok", node.getText());
  if (ts.isTypeReferenceNode(node)) {
    const tn = node.typeName;
    if (ts.isQualifiedName(tn)) {
      if (ts.isIdentifier(tn.left)) {
        const decl = declarationOf(tn.left.text, node);
        const origin = decl === undefined ? undefined : importOrigin(decl);
        if (origin !== undefined && origin.imported === "*" && originIsFloor(origin, abs, ctx.floor) && (tn.right.text === "FloorCount" || tn.right.text === "FloorTotal")) {
          return leaf("floor", tn.right.text);
        }
      }
      return leaf("unresolved", node.getText());
    }
    return referenceTree(tn.text, node.typeArguments, node, abs, ctx);
  }
  switch (node.kind) {
    case ts.SyntaxKind.NumberKeyword:
      return leaf("number", "number");
    case ts.SyntaxKind.BigIntKeyword:
      return leaf("bigint", "bigint");
    case ts.SyntaxKind.AnyKeyword:
      return leaf("any", "any");
    case ts.SyntaxKind.UnknownKeyword:
      return leaf("unknown", "unknown");
    case ts.SyntaxKind.ObjectKeyword:
      return leaf("unresolved", "object");
    case ts.SyntaxKind.UndefinedKeyword:
    case ts.SyntaxKind.VoidKeyword:
    case ts.SyntaxKind.NullKeyword:
      return leaf("nullish", node.getText());
    case ts.SyntaxKind.StringKeyword:
    case ts.SyntaxKind.BooleanKeyword:
    case ts.SyntaxKind.NeverKeyword:
    case ts.SyntaxKind.SymbolKeyword:
      return leaf("ok", node.getText());
    default:
      return leaf("unresolved", node.getText());
  }
}

/* ── values to trees ─────────────────────────────────────────────────────── */

export function valueTree(expr: ts.Expression, sf: ts.SourceFile, seen: Set<string> = new Set()): Tree {
  const e = unwrapExpression(expr);
  if (ts.isObjectLiteralExpression(e)) {
    const members = new Map<string, Tree>();
    for (const p of e.properties) {
      if (ts.isPropertyAssignment(p)) {
        const name = propName(p.name);
        if (name !== undefined) members.set(name, valueTree(p.initializer, sf, seen));
      } else if (ts.isShorthandPropertyAssignment(p)) {
        members.set(p.name.text, identifierValue(p.name.text, sf, seen));
      } else if (ts.isSpreadAssignment(p)) {
        const inner = unwrapExpression(p.expression);
        const spread = ts.isIdentifier(inner) ? identifierValue(inner.text, sf, seen) : leaf("computed", "a spread");
        if (spread.kind === "object") for (const [k, v] of spread.members) members.set(k, v);
        else members.set("...", leaf("computed", "a spread the floor cannot read"));
      }
    }
    return { kind: "object", members };
  }
  if (ts.isArrayLiteralExpression(e)) {
    const els = e.elements.map((x) => (ts.isSpreadElement(x) ? leaf("computed", "a spread") : valueTree(x, sf, seen)));
    return { kind: "array", element: els.length === 0 ? leaf("nullish", "[]") : els.reduce((a, b) => mergeTrees(a, b)) };
  }
  if (ts.isCallExpression(e) && e.arguments.length === 1 && e.expression.getText() === "Object.freeze") {
    return valueTree(e.arguments[0]!, sf, seen);
  }
  if (ts.isIdentifier(e)) return identifierValue(e.text, sf, seen);
  if (ts.isNumericLiteral(e)) return leaf("num", e.text);
  if (ts.isPrefixUnaryExpression(e) && e.operator === ts.SyntaxKind.MinusToken && ts.isNumericLiteral(e.operand)) return leaf("num", `-${e.operand.text}`);
  if (ts.isStringLiteral(e) || ts.isNoSubstitutionTemplateLiteral(e)) return leaf("str", e.text);
  if (e.kind === ts.SyntaxKind.TrueKeyword || e.kind === ts.SyntaxKind.FalseKeyword || e.kind === ts.SyntaxKind.NullKeyword) return leaf("lit", e.getText());
  return leaf("computed", e.getText().slice(0, 60));
}

function identifierValue(name: string, sf: ts.SourceFile, seen: Set<string>): Tree {
  if (name === "undefined") return leaf("lit", "undefined");
  if (seen.has(name)) return leaf("computed", name);
  const init = constInitializer(sf, name);
  if (init === undefined) return leaf("computed", name);
  seen.add(name);
  try {
    return valueTree(init, sf, seen);
  } finally {
    seen.delete(name);
  }
}

/** A numeric literal, or a decimal string such as "1.00": the shape a price takes. */
export function isPriceValue(l: LeafAt): boolean {
  return l.cls === "num" || (l.cls === "str" && /^\s*\d+(?:[.,]\d+)?\s*$/.test(l.text));
}
