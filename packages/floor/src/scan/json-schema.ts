/**
 * Lexicons written as JSON Schema: every object in a schema, with its properties, what it requires, and where it is.
 * A lexicon's name comes from its `$id` (`…/kash.decision@1.2.0` → `kash.decision`), an `id`/`nsid`, or its file.
 */

export interface SchemaObject {
  /** JSON pointer of the object in its document. */
  readonly pointer: string;
  readonly properties: ReadonlyMap<string, unknown>;
  readonly required: readonly string[];
  /** Pointer of the enclosing object, if any. */
  readonly parent: string | undefined;
}

export interface LexiconDoc {
  readonly file: string;
  readonly name: string;
  readonly objects: readonly SchemaObject[];
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

export function lexiconName(doc: unknown, file: string): string {
  if (isObj(doc)) {
    for (const k of ["$id", "id", "nsid", "lexicon"]) {
      const v = doc[k];
      if (typeof v === "string" && v !== "") {
        // `…/attestation-vc/1.json` is named attestation-vc: a version segment is not a name.
        const segs = v.split("/").map((s) => s.replace(/@.*$/, "").replace(/\.schema\.json$/, "").replace(/\.json$/, "")).filter((s) => s !== "");
        while (segs.length > 1 && /^v?\d+(\.\d+)*$/.test(segs[segs.length - 1]!)) segs.pop();
        return segs[segs.length - 1] ?? v;
      }
    }
  }
  return (file.split("/").pop() ?? file).replace(/\.schema\.json$/, "").replace(/\.json$/, "");
}

/** Every object (a schema with `properties`) in a document, depth first. */
export function schemaObjects(doc: unknown): SchemaObject[] {
  const out: SchemaObject[] = [];
  const visit = (node: unknown, pointer: string, parent: string | undefined): void => {
    if (Array.isArray(node)) {
      node.forEach((v, i) => visit(v, `${pointer}/${i}`, parent));
      return;
    }
    if (!isObj(node)) return;
    let here = parent;
    if (isObj(node.properties)) {
      const props = new Map(Object.entries(node.properties));
      const required = Array.isArray(node.required) ? node.required.filter((r): r is string => typeof r === "string") : [];
      out.push({ pointer: pointer === "" ? "/" : pointer, properties: props, required, parent });
      here = pointer === "" ? "/" : pointer;
    }
    for (const [k, v] of Object.entries(node)) {
      if (k === "properties" && isObj(v)) {
        for (const [pk, pv] of Object.entries(v)) visit(pv, `${pointer}/properties/${pk}`, here);
      } else if (k === "enum" || k === "const" || k === "examples" || k === "default" || k === "required") {
        continue;
      } else {
        visit(v, `${pointer}/${k}`, here);
      }
    }
  };
  visit(doc, "", undefined);
  return out;
}

export function readLexiconJson(file: string, text: string): LexiconDoc | { readonly file: string; readonly error: string } {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    return { file, error: (e as Error).message };
  }
  return { file, name: lexiconName(doc, file), objects: schemaObjects(doc) };
}

/** The sub-schema at a property of an object, if it is itself an object schema. */
export function propertySchema(obj: SchemaObject, name: string): Record<string, unknown> | undefined {
  const v = obj.properties.get(name);
  return isObj(v) ? v : undefined;
}
