/**
 * A Prisma schema, read enough for the floor: models (and views and composite types) with their fields, and enums.
 * Several files may make one schema (Prisma's schema folder); relations are resolved across all of them.
 */

export interface PrismaField {
  readonly name: string;
  readonly type: string;
  readonly optional: boolean;
  readonly list: boolean;
  readonly attrs: string;
  /** Set after every file is read: the field's type is a model. */
  relation: boolean;
}

export interface PrismaModel {
  readonly name: string;
  /** The table's name: @@map's, else the model's. */
  dbName: string;
  readonly kind: "model" | "view" | "type";
  readonly fields: PrismaField[];
  readonly file: string;
}

export interface PrismaSchema {
  readonly models: Map<string, PrismaModel>;
  readonly enums: Map<string, string[]>;
}

/** Remove `//` comments outside string literals, keeping the line structure. */
function stripComments(text: string): string {
  const out: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    let inStr = false;
    let cut = line.length;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (c === "\\" && inStr) {
        i++;
        continue;
      }
      if (c === '"') inStr = !inStr;
      else if (!inStr && c === "/" && line[i + 1] === "/") {
        cut = i;
        break;
      }
    }
    out.push(line.slice(0, cut));
  }
  return out.join("\n");
}

export function emptySchema(): PrismaSchema {
  return { models: new Map(), enums: new Map() };
}

/** Add one file's blocks to a schema. */
export function readPrisma(schema: PrismaSchema, file: string, text: string): void {
  const src = stripComments(text);
  const head = /^\s*(model|view|type|enum)\s+(\w+)\s*\{/gm;
  let m: RegExpExecArray | null;
  while ((m = head.exec(src)) !== null) {
    const kind = m[1] as "model" | "view" | "type" | "enum";
    const name = m[2]!;
    // The block's end: the matching brace, counting braces outside strings.
    let depth = 1;
    let i = head.lastIndex;
    let inStr = false;
    for (; i < src.length && depth > 0; i++) {
      const c = src[i];
      if (c === "\\" && inStr) {
        i++;
        continue;
      }
      if (c === '"') inStr = !inStr;
      else if (!inStr && c === "{") depth++;
      else if (!inStr && c === "}") depth--;
    }
    const body = src.slice(head.lastIndex, i - 1);
    head.lastIndex = i;
    if (kind === "enum") {
      // One value per line as Prisma formats it, or several on a line; attributes (@map, @@map) are not values.
      const bare = body
        .split("\n")
        .filter((l) => !l.trim().startsWith("@@"))
        .join(" ")
        .replace(/@[\w.]+(?:\([^)]*\))?/g, " ");
      schema.enums.set(name, bare.split(/\s+/).filter((v) => /^[A-Za-z_]\w*$/.test(v)));
      continue;
    }
    const model: PrismaModel = { name, dbName: name, kind, fields: [], file };
    for (const raw of body.split("\n")) {
      const line = raw.trim();
      if (line === "") continue;
      if (line.startsWith("@@")) {
        const map = /^@@map\(\s*(?:name\s*:\s*)?"([^"]+)"/.exec(line);
        if (map !== null) model.dbName = map[1]!;
        continue;
      }
      const f = /^([A-Za-z_]\w*)\s+([\w.]+(?:\([^)]*\))?)(\[\])?(\?)?\s*(.*)$/.exec(line);
      if (f === null) continue;
      model.fields.push({ name: f[1]!, type: f[2]!, list: f[3] !== undefined, optional: f[4] !== undefined, attrs: f[5] ?? "", relation: false });
    }
    schema.models.set(name, model);
  }
}

/** After every file: mark relation fields. */
export function resolveRelations(schema: PrismaSchema): void {
  for (const model of schema.models.values()) {
    for (const field of model.fields) field.relation = schema.models.has(field.type);
  }
}

/** Is a field non-null? A required scalar, or the id. */
export function prismaNonNull(field: PrismaField): boolean {
  return !field.optional && !field.list;
}
