/**
 * Postgres DDL, read in migration order, enough for the floor: tables and their columns, check-constraint and enum
 * values, views, functions and their bodies, drops and renames, row-level security, policies, grants and revokes.
 *
 * Comments are skipped; quoted strings, quoted identifiers and dollar-quoted bodies are kept whole, so a `create
 * table` written inside a function body is never read as one. Default privileges are not read: Supabase's defaults
 * are assumed (tables selectable by anon and authenticated; functions executable by public, anon and authenticated),
 * so when the floor is unsure, an object counts as open.
 */

export interface SqlColumn {
  name: string;
  type: string;
  notNull: boolean;
  references: string | undefined;
  values: string[];
}

export interface SqlPolicy {
  name: string;
  command: string;
  roles: string[];
  using: string;
}

export interface SqlRelation {
  schema: string;
  name: string;
  kind: "table" | "view";
  readonly columns: Map<string, SqlColumn>;
  readonly checks: Map<string, { column: string | undefined; values: string[] }>;
  rls: boolean;
  readonly policies: Map<string, SqlPolicy>;
  readonly selectRoles: Set<string>;
  body: string;
  file: string;
}

export interface SqlFunction {
  schema: string;
  name: string;
  returns: string;
  /** `returns setof <table>`: the table's name. */
  returnsSetOf: string | undefined;
  /** The parameters' names. */
  args: string[];
  trigger: boolean;
  body: string;
  readonly executeRoles: Set<string>;
  file: string;
}

export interface SqlModel {
  readonly relations: Map<string, SqlRelation>;
  readonly functions: Map<string, SqlFunction>;
  readonly enums: Map<string, string[]>;
}

export function emptySqlModel(): SqlModel {
  return { relations: new Map(), functions: new Map(), enums: new Map() };
}

const CLIENT_TABLE_ROLES = ["anon", "authenticated"];
const CLIENT_FUNCTION_ROLES = ["public", "anon", "authenticated"];

/* ── lexing ───────────────────────────────────────────────────────────────── */

/** Statements, split on top-level semicolons, with comments removed and strings and bodies kept. */
export function statements(text: string): string[] {
  const out: string[] = [];
  let cur = "";
  const n = text.length;
  let i = 0;
  while (i < n) {
    const c = text[i]!;
    if (c === "-" && text[i + 1] === "-") {
      while (i < n && text[i] !== "\n") i++;
      cur += " ";
      continue;
    }
    if (c === "/" && text[i + 1] === "*") {
      let depth = 1;
      i += 2;
      while (i < n && depth > 0) {
        if (text[i] === "/" && text[i + 1] === "*") {
          depth++;
          i += 2;
        } else if (text[i] === "*" && text[i + 1] === "/") {
          depth--;
          i += 2;
        } else i++;
      }
      cur += " ";
      continue;
    }
    if (c === "'") {
      const before = cur[cur.length - 1];
      const escaped = (before === "E" || before === "e") && !/[A-Za-z0-9_]/.test(cur[cur.length - 2] ?? " ");
      let j = i + 1;
      while (j < n) {
        if (escaped && text[j] === "\\") {
          j += 2;
          continue;
        }
        if (text[j] === "'") {
          if (text[j + 1] === "'") {
            j += 2;
            continue;
          }
          break;
        }
        j++;
      }
      cur += text.slice(i, j + 1);
      i = j + 1;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      while (j < n) {
        if (text[j] === '"') {
          if (text[j + 1] === '"') {
            j += 2;
            continue;
          }
          break;
        }
        j++;
      }
      cur += text.slice(i, j + 1);
      i = j + 1;
      continue;
    }
    if (c === "$") {
      const m = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(text.slice(i, i + 80));
      if (m !== null) {
        const tag = m[0];
        const end = text.indexOf(tag, i + tag.length);
        const stop = end < 0 ? n : end + tag.length;
        cur += text.slice(i, stop);
        i = stop;
        continue;
      }
    }
    if (c === ";") {
      if (cur.trim() !== "") out.push(cur.trim());
      cur = "";
      i++;
      continue;
    }
    cur += c;
    i++;
  }
  if (cur.trim() !== "") out.push(cur.trim());
  return out;
}

/** Skip a quoted string, identifier or dollar body starting at `i`; returns the index after it, or `i` if none. */
function skipQuoted(s: string, i: number): number {
  const c = s[i];
  if (c === "'" || c === '"') {
    let j = i + 1;
    while (j < s.length) {
      if (s[j] === c) {
        if (s[j + 1] === c) {
          j += 2;
          continue;
        }
        return j + 1;
      }
      j++;
    }
    return s.length;
  }
  if (c === "$") {
    const m = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(s.slice(i, i + 80));
    if (m !== null) {
      const end = s.indexOf(m[0], i + m[0].length);
      return end < 0 ? s.length : end + m[0].length;
    }
  }
  return i;
}

/** The text inside the parenthesis that opens at `open`, and the index after its close. */
export function balanced(s: string, open: number): { inner: string; end: number } | undefined {
  if (s[open] !== "(") return undefined;
  let depth = 0;
  for (let i = open; i < s.length; i++) {
    const skip = skipQuoted(s, i);
    if (skip !== i) {
      i = skip - 1;
      continue;
    }
    if (s[i] === "(") depth++;
    else if (s[i] === ")") {
      depth--;
      if (depth === 0) return { inner: s.slice(open + 1, i), end: i + 1 };
    }
  }
  return undefined;
}

/** Split on commas outside parentheses and quotes. */
export function splitTop(s: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    const skip = skipQuoted(s, i);
    if (skip !== i) {
      i = skip - 1;
      continue;
    }
    if (s[i] === "(") depth++;
    else if (s[i] === ")") depth--;
    else if (s[i] === "," && depth === 0) {
      out.push(s.slice(start, i).trim());
      start = i + 1;
    }
  }
  const last = s.slice(start).trim();
  if (last !== "") out.push(last);
  return out;
}

const IDENT = String.raw`(?:"(?:[^"]|"")+"|[A-Za-z_][\w$]*)`;

function unquote(id: string): string {
  return id.startsWith('"') ? id.slice(1, -1).replace(/""/g, '"') : id.toLowerCase();
}

/** A possibly schema-qualified name at `pos` (after whitespace). */
export function identAt(s: string, pos: number): { schema: string | undefined; name: string; end: number } | undefined {
  const re = new RegExp(String.raw`^\s*(${IDENT})(?:\s*\.\s*(${IDENT}))?`);
  const m = re.exec(s.slice(pos));
  if (m === null) return undefined;
  const end = pos + m[0].length;
  return m[2] !== undefined ? { schema: unquote(m[1]!), name: unquote(m[2]), end } : { schema: undefined, name: unquote(m[1]!), end };
}

/** Every single-quoted literal in a piece of SQL. */
export function literals(s: string): string[] {
  return [...s.matchAll(/'((?:[^']|'')*)'/g)].map((m) => m[1]!.replace(/''/g, "'"));
}

const key = (schema: string | undefined, name: string): string => `${schema ?? "public"}.${name}`;

/* ── reading ──────────────────────────────────────────────────────────────── */

const COLUMN_STOP = /\s(?:not\s+null|null|default|references|check|primary\s+key|unique|constraint|generated|collate)\b/i;

function guessCheckColumn(expr: string, rel: SqlRelation): string | undefined {
  const m = /("?[A-Za-z_][\w$]*"?)\s*(?:::\s*[\w ]+?\s*)?(?:\bin\s*\(|=\s*any\b|=)/i.exec(expr);
  if (m !== null) {
    const name = unquote(m[1]!);
    if (rel.columns.has(name)) return name;
  }
  for (const name of rel.columns.keys()) if (new RegExp(String.raw`\b${name}\b`, "i").test(expr)) return name;
  return undefined;
}

function addCheck(rel: SqlRelation, name: string, expr: string, column: string | undefined): void {
  rel.checks.set(name, { column: column ?? guessCheckColumn(expr, rel), values: literals(expr) });
}

function readColumn(rel: SqlRelation, element: string, checkSeq: () => string): void {
  const id = identAt(element, 0);
  if (id === undefined) return;
  const rest = element.slice(id.end);
  const stop = COLUMN_STOP.exec(rest);
  const type = (stop === null ? rest : rest.slice(0, stop.index)).trim().toLowerCase();
  const ref = new RegExp(String.raw`\breferences\s+(${IDENT}(?:\s*\.\s*${IDENT})?)`, "i").exec(rest);
  const col: SqlColumn = {
    name: id.name,
    type,
    notNull: /\bnot\s+null\b/i.test(rest) || /\bprimary\s+key\b/i.test(rest),
    references: ref === null ? undefined : (identAt(ref[1]!, 0)?.name ?? undefined),
    values: [],
  };
  rel.columns.set(col.name, col);
  const chk = /\bcheck\s*\(/i.exec(rest);
  if (chk !== null) {
    const grp = balanced(rest, chk.index + chk[0].length - 1);
    if (grp !== undefined) addCheck(rel, checkSeq(), grp.inner, col.name);
  }
}

function newRelation(schema: string, name: string, kind: "table" | "view", file: string): SqlRelation {
  return { schema, name, kind, columns: new Map(), checks: new Map(), rls: false, policies: new Map(), selectRoles: new Set(CLIENT_TABLE_ROLES), body: "", file };
}

function roleList(s: string): string[] {
  return s
    .replace(/\bwith\s+grant\s+option\b/gi, "")
    .replace(/\bgranted\s+by\s+\S+/gi, "")
    .replace(/\b(cascade|restrict)\b/gi, "")
    .split(",")
    .map((r) => r.trim())
    .filter((r) => r !== "")
    .map((r) => unquote(r.replace(/^group\s+/i, "")));
}

/** Add one migration file's statements to the model, in order. */
export function readSql(model: SqlModel, file: string, text: string): void {
  let anon = 0;
  for (const st of statements(text)) {
    const seq = (): string => `${file}#check${++anon}`;

    let m = /^create\s+(?:(?:global|local)\s+)?(?:(?:temporary|temp|unlogged)\s+)?table\s+(?:if\s+not\s+exists\s+)?/i.exec(st);
    if (m !== null) {
      const id = identAt(st, m[0].length);
      if (id === undefined) continue;
      const k = key(id.schema, id.name);
      const rel = model.relations.get(k) ?? newRelation(id.schema ?? "public", id.name, "table", file);
      model.relations.set(k, rel);
      const open = st.indexOf("(", id.end);
      if (open < 0 || /^\s*(as|partition\s+of)\b/i.test(st.slice(id.end))) continue;
      const grp = balanced(st, open);
      if (grp === undefined) continue;
      for (const el of splitTop(grp.inner)) {
        const cons = /^(?:constraint\s+(\S+)\s+)?(primary\s+key|foreign\s+key|unique|check|exclude|like)\b/i.exec(el);
        if (cons !== null) {
          if (cons[2]!.toLowerCase() === "check") {
            const g = balanced(el, el.indexOf("(", cons[0].length - 1));
            if (g !== undefined) addCheck(rel, cons[1] !== undefined ? unquote(cons[1]) : seq(), g.inner, undefined);
          }
          continue;
        }
        readColumn(rel, el, seq);
      }
      continue;
    }

    m = /^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?/i.exec(st);
    if (m !== null) {
      const id = identAt(st, m[0].length);
      if (id === undefined) continue;
      let k = key(id.schema, id.name);
      const rel = model.relations.get(k);
      if (rel === undefined) continue;
      for (const action of splitTop(st.slice(id.end))) {
        let a: RegExpExecArray | null;
        if (/^enable\s+row\s+level\s+security/i.test(action)) rel.rls = true;
        else if (/^disable\s+row\s+level\s+security/i.test(action)) rel.rls = false;
        else if ((a = /^add\s+(?:constraint\s+(\S+)\s+)?check\s*\(/i.exec(action)) !== null) {
          const g = balanced(action, a[0].length - 1);
          if (g !== undefined) addCheck(rel, a[1] !== undefined ? unquote(a[1]) : seq(), g.inner, undefined);
        } else if (/^add\s+(?:constraint\s+\S+\s+)?(?:primary\s+key|foreign\s+key|unique|exclude)\b/i.test(action)) {
          continue;
        } else if ((a = /^add\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?/i.exec(action)) !== null) {
          readColumn(rel, action.slice(a[0].length), seq);
        } else if ((a = /^drop\s+constraint\s+(?:if\s+exists\s+)?/i.exec(action)) !== null) {
          const c = identAt(action, a[0].length);
          if (c !== undefined) rel.checks.delete(c.name);
        } else if ((a = /^drop\s+(?:column\s+)?(?:if\s+exists\s+)?/i.exec(action)) !== null) {
          const c = identAt(action, a[0].length);
          if (c !== undefined) {
            rel.columns.delete(c.name);
            for (const [n, chk] of rel.checks) if (chk.column === c.name) rel.checks.delete(n);
          }
        } else if ((a = /^rename\s+to\s+/i.exec(action)) !== null) {
          const c = identAt(action, a[0].length);
          if (c !== undefined) {
            model.relations.delete(k);
            rel.name = c.name;
            k = key(rel.schema, rel.name);
            model.relations.set(k, rel);
          }
        } else if ((a = /^set\s+schema\s+/i.exec(action)) !== null) {
          const c = identAt(action, a[0].length);
          if (c !== undefined) {
            model.relations.delete(k);
            rel.schema = c.name;
            k = key(rel.schema, rel.name);
            model.relations.set(k, rel);
          }
        } else if (/^rename\s+constraint\b/i.test(action)) {
          continue;
        } else if ((a = new RegExp(String.raw`^rename\s+(?:column\s+)?(${IDENT})\s+to\s+(${IDENT})`, "i").exec(action)) !== null) {
          const from = unquote(a[1]!);
          const to = unquote(a[2]!);
          const col = rel.columns.get(from);
          if (col !== undefined) {
            rel.columns.delete(from);
            col.name = to;
            rel.columns.set(to, col);
            for (const chk of rel.checks.values()) if (chk.column === from) chk.column = to;
          }
        } else if ((a = new RegExp(String.raw`^alter\s+(?:column\s+)?(${IDENT})\s+(set|drop)\s+not\s+null`, "i").exec(action)) !== null) {
          const col = rel.columns.get(unquote(a[1]!));
          if (col !== undefined) col.notNull = a[2]!.toLowerCase() === "set";
        } else if ((a = new RegExp(String.raw`^alter\s+(?:column\s+)?(${IDENT})\s+(?:set\s+data\s+)?type\s+(.+)$`, "is").exec(action)) !== null) {
          const col = rel.columns.get(unquote(a[1]!));
          if (col !== undefined) col.type = a[2]!.replace(/\busing\b[\s\S]*$/i, "").trim().toLowerCase();
        }
      }
      continue;
    }

    m = /^create\s+(?:or\s+replace\s+)?(?:(?:temporary|temp)\s+)?(?:recursive\s+)?(?:materialized\s+)?view\s+(?:if\s+not\s+exists\s+)?/i.exec(st);
    if (m !== null) {
      const id = identAt(st, m[0].length);
      if (id === undefined) continue;
      const k = key(id.schema, id.name);
      const rel = model.relations.get(k) ?? newRelation(id.schema ?? "public", id.name, "view", file);
      rel.body = st;
      rel.file = file;
      model.relations.set(k, rel);
      continue;
    }

    m = /^create\s+(?:or\s+replace\s+)?function\s+/i.exec(st);
    if (m !== null) {
      const id = identAt(st, m[0].length);
      if (id === undefined) continue;
      const open = st.indexOf("(", id.end);
      const args = open < 0 ? undefined : balanced(st, open);
      const after = args === undefined ? st.slice(id.end) : st.slice(args.end);
      const ret = /\breturns\s+(setof\s+)?(table\s*\(|[\w."[\] ]+?)(?=\s+(?:language|as|immutable|stable|volatile|security|set|strict|called|parallel|cost|rows|begin|return)\b|\s*$|\s+\$)/i.exec(after);
      const dollar = /\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(after);
      let body = "";
      if (dollar !== null) {
        const startBody = dollar.index + dollar[0].length;
        const endBody = after.indexOf(dollar[0], startBody);
        body = after.slice(startBody, endBody < 0 ? undefined : endBody);
      } else {
        body = literals(after).join("\n");
      }
      const k = key(id.schema, id.name);
      const prior = model.functions.get(k);
      const returns = (ret?.[2] ?? "").trim().toLowerCase();
      const argNames = (args === undefined ? [] : splitTop(args.inner))
        .map((a) => a.replace(/^\s*(in|out|inout|variadic)\s+/i, ""))
        .map((a) => identAt(a, 0)?.name)
        .filter((n): n is string => n !== undefined);
      const setof = ret?.[1] !== undefined ? identAt(ret[2] ?? "", 0)?.name : undefined;
      const fn: SqlFunction = {
        schema: id.schema ?? "public",
        name: id.name,
        returns,
        returnsSetOf: setof,
        args: argNames,
        trigger: /^(event_)?trigger\b/.test(returns),
        body,
        executeRoles: prior?.executeRoles ?? new Set(CLIENT_FUNCTION_ROLES),
        file,
      };
      model.functions.set(k, fn);
      continue;
    }

    m = /^create\s+type\s+/i.exec(st);
    if (m !== null) {
      const id = identAt(st, m[0].length);
      if (id === undefined) continue;
      const e = /^\s*as\s+enum\s*\(/i.exec(st.slice(id.end));
      if (e === null) continue;
      const g = balanced(st, id.end + e[0].length - 1);
      model.enums.set(id.name, g === undefined ? [] : literals(g.inner));
      continue;
    }

    m = /^alter\s+type\s+/i.exec(st);
    if (m !== null) {
      const id = identAt(st, m[0].length);
      if (id === undefined) continue;
      const values = model.enums.get(id.name);
      if (values === undefined) continue;
      const add = /add\s+value\s+(?:if\s+not\s+exists\s+)?'((?:[^']|'')*)'/i.exec(st);
      if (add !== null && !values.includes(add[1]!)) values.push(add[1]!.replace(/''/g, "'"));
      const ren = /rename\s+value\s+'((?:[^']|'')*)'\s+to\s+'((?:[^']|'')*)'/i.exec(st);
      if (ren !== null) {
        const at = values.indexOf(ren[1]!);
        if (at >= 0) values[at] = ren[2]!;
      }
      continue;
    }

    m = /^drop\s+(table|materialized\s+view|view|function|type)\s+(?:if\s+exists\s+)?/i.exec(st);
    if (m !== null) {
      const what = m[1]!.toLowerCase();
      for (const part of splitTop(st.slice(m[0].length).replace(/\b(cascade|restrict)\s*$/i, ""))) {
        const id = identAt(part, 0);
        if (id === undefined) continue;
        const k = key(id.schema, id.name);
        if (what === "function") model.functions.delete(k);
        else if (what === "type") model.enums.delete(id.name);
        else model.relations.delete(k);
      }
      continue;
    }

    m = /^create\s+policy\s+/i.exec(st);
    if (m !== null) {
      const name = identAt(st, m[0].length);
      if (name === undefined) continue;
      const on = /^\s+on\s+/i.exec(st.slice(name.end));
      if (on === null) continue;
      const tbl = identAt(st, name.end + on[0].length);
      if (tbl === undefined) continue;
      const rel = model.relations.get(key(tbl.schema, tbl.name));
      if (rel === undefined) continue;
      const rest = st.slice(tbl.end);
      const cmd = /\bfor\s+(all|select|insert|update|delete)\b/i.exec(rest);
      const to = /\bto\s+([\s\S]+?)(?=\s+using\b|\s+with\s+check\b|$)/i.exec(rest);
      const using = /\busing\s*\(/i.exec(rest);
      const usingExpr = using === null ? "" : (balanced(rest, using.index + using[0].length - 1)?.inner ?? "");
      rel.policies.set(name.name, {
        name: name.name,
        command: (cmd?.[1] ?? "all").toLowerCase(),
        roles: to === null ? ["public"] : roleList(to[1]!),
        using: usingExpr,
      });
      continue;
    }

    m = /^drop\s+policy\s+(?:if\s+exists\s+)?/i.exec(st);
    if (m !== null) {
      const name = identAt(st, m[0].length);
      if (name === undefined) continue;
      const on = /^\s+on\s+/i.exec(st.slice(name.end));
      if (on === null) continue;
      const tbl = identAt(st, name.end + on[0].length);
      if (tbl !== undefined) model.relations.get(key(tbl.schema, tbl.name))?.policies.delete(name.name);
      continue;
    }

    m = /^alter\s+policy\s+/i.exec(st);
    if (m !== null) {
      const name = identAt(st, m[0].length);
      if (name === undefined) continue;
      const on = /^\s+on\s+/i.exec(st.slice(name.end));
      if (on === null) continue;
      const tbl = identAt(st, name.end + on[0].length);
      if (tbl === undefined) continue;
      const rel = model.relations.get(key(tbl.schema, tbl.name));
      const pol = rel?.policies.get(name.name);
      if (rel === undefined || pol === undefined) continue;
      const rest = st.slice(tbl.end);
      const rename = /^\s*rename\s+to\s+/i.exec(rest);
      if (rename !== null) {
        const to = identAt(rest, rename[0].length);
        if (to !== undefined) {
          rel.policies.delete(pol.name);
          pol.name = to.name;
          rel.policies.set(pol.name, pol);
        }
        continue;
      }
      const to = /\bto\s+([\s\S]+?)(?=\s+using\b|\s+with\s+check\b|$)/i.exec(rest);
      if (to !== null) pol.roles = roleList(to[1]!);
      const using = /\busing\s*\(/i.exec(rest);
      if (using !== null) pol.using = balanced(rest, using.index + using[0].length - 1)?.inner ?? pol.using;
      continue;
    }

    m = /^(grant|revoke)\s+(?:grant\s+option\s+for\s+)?([\s\S]+?)\s+on\s+([\s\S]+?)\s+(to|from)\s+([\s\S]+)$/i.exec(st);
    if (m !== null) {
      const granting = m[1]!.toLowerCase() === "grant";
      const privs = m[2]!.toLowerCase();
      const objects = m[3]!.trim();
      const roles = roleList(m[5]!);
      const apply = (set: Set<string>): void => {
        for (const r of roles) {
          if (granting) set.add(r);
          else set.delete(r);
        }
      };
      const selects = /\b(select|all)\b/.test(privs);
      const executes = /\b(execute|all)\b/.test(privs);
      let a: RegExpExecArray | null;
      if ((a = /^all\s+tables\s+in\s+schema\s+([\s\S]+)$/i.exec(objects)) !== null) {
        const schemas = splitTop(a[1]!).map((s) => unquote(s.trim()));
        if (selects) for (const rel of model.relations.values()) if (schemas.includes(rel.schema)) apply(rel.selectRoles);
      } else if ((a = /^all\s+(?:functions|routines)\s+in\s+schema\s+([\s\S]+)$/i.exec(objects)) !== null) {
        const schemas = splitTop(a[1]!).map((s) => unquote(s.trim()));
        if (executes) for (const fn of model.functions.values()) if (schemas.includes(fn.schema)) apply(fn.executeRoles);
      } else if ((a = /^(?:function|routine)\s+([\s\S]+)$/i.exec(objects)) !== null) {
        if (executes) {
          for (const part of splitTop(a[1]!)) {
            const id = identAt(part, 0);
            const fn = id === undefined ? undefined : model.functions.get(key(id.schema, id.name));
            if (fn !== undefined) apply(fn.executeRoles);
          }
        }
      } else if (/^(sequence|schema|database|domain|type|language|large\s+object|foreign|tablespace|procedure)\b/i.test(objects)) {
        // not data PostgREST serves
      } else if (selects) {
        for (const part of splitTop(objects.replace(/^table\s+/i, ""))) {
          const id = identAt(part, 0);
          const rel = id === undefined ? undefined : model.relations.get(key(id.schema, id.name));
          if (rel !== undefined) apply(rel.selectRoles);
        }
      }
      continue;
    }
  }
}

/* ── reading the model ────────────────────────────────────────────────────── */

/** A column's allowed values: its check constraints' literals and its enum type's values. */
export function columnValues(model: SqlModel, rel: SqlRelation, column: SqlColumn): string[] {
  const out = new Set<string>(column.values);
  for (const chk of rel.checks.values()) if (chk.column === column.name) for (const v of chk.values) out.add(v);
  const typeName = column.type.replace(/\[\]$/, "").split(".").pop() ?? column.type;
  for (const v of model.enums.get(typeName.replace(/"/g, "")) ?? []) out.add(v);
  return [...out];
}

/** Policies a client role can read rows through. */
export function clientSelectPolicies(rel: SqlRelation): SqlPolicy[] {
  return [...rel.policies.values()].filter(
    (p) => (p.command === "select" || p.command === "all") && p.roles.some((r) => r === "public" || CLIENT_TABLE_ROLES.includes(r)),
  );
}

/** No client can read it: no client role holds select, or row-level security is on and no policy lets one through. */
export function relationClosed(rel: SqlRelation): boolean {
  const granted = CLIENT_TABLE_ROLES.some((r) => rel.selectRoles.has(r));
  if (!granted) return true;
  return rel.kind === "table" && rel.rls && clientSelectPolicies(rel).length === 0;
}

/** Rows keyed to the caller: row-level security on, and every client read policy uses auth.uid(). */
/** `col = auth.uid()` or `auth.uid() = col` (with or without `select`): rows keyed to the caller, not merely signed in. */
const KEYED_TO_CALLER = /[\w."]+\s*=\s*\(?\s*(?:select\s+)?auth\s*\.\s*uid\s*\(\s*\)\s*\)?|\(?\s*(?:select\s+)?auth\s*\.\s*uid\s*\(\s*\)\s*\)?\s*=\s*[\w."]+/i;

export function relationSelf(rel: SqlRelation): boolean {
  const pols = clientSelectPolicies(rel);
  return rel.kind === "table" && rel.rls && pols.length > 0 && pols.every((p) => KEYED_TO_CALLER.test(p.using));
}

export function functionClosed(fn: SqlFunction): boolean {
  return !CLIENT_FUNCTION_ROLES.some((r) => fn.executeRoles.has(r));
}

/** Does this SQL count or sum? */
/** Functions that count, sum or average people's acts, or measure a list. */
const COUNT_FNS = String.raw`\b(count|sum|avg|cardinality|array_length|jsonb_array_length)\s*\(`;

export function countsIn(sql: string): boolean {
  return new RegExp(COUNT_FNS, "i").test(stripStrings(sql));
}

function stripStrings(sql: string): string {
  return sql.replace(/'(?:[^']|'')*'/g, "''");
}

/** Every count( and sum( inside a floor_suppress( call. */
export function everyCountWrapped(sql: string): { wrapped: boolean; bare: number } {
  const text = stripStrings(sql);
  const spans: Array<[number, number]> = [];
  for (const m of text.matchAll(/\bfloor_suppress\s*\(/gi)) {
    const open = m.index + m[0].length - 1;
    const g = balanced(text, open);
    if (g !== undefined) spans.push([open, g.end]);
  }
  let bare = 0;
  for (const m of text.matchAll(new RegExp(COUNT_FNS, "gi"))) {
    if (!spans.some(([a, b]) => m.index > a && m.index < b)) bare++;
  }
  return { wrapped: bare === 0, bare };
}

/** The body @kashscript/floor ships for floor_suppress (sql/floor_suppress.sql), compared without strings or spacing. */
const CANONICAL_FLOOR_SUPPRESS =
  "begin if k is null or k < 5 then raise exception 'x', k; end if; if n is null or n < k then return null; end if; return n; end;";

function normalBody(body: string): string {
  return stripStrings(body).replace(/\s+/g, " ").replace(/\s*([;,()<=])\s*/g, "$1").trim().toLowerCase();
}

/** Is this the floor's own floor_suppress, unchanged? A counterfeit that returns n whole would pass every wrap check. */
export function isCanonicalFloorSuppress(fn: SqlFunction): boolean {
  return normalBody(fn.body) === normalBody(CANONICAL_FLOOR_SUPPRESS) && fn.returnsSetOf === undefined;
}
