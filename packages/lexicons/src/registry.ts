/**
 * LexiconRegistry — agnostic storage for Lexicon definitions.
 *
 * The registry holds a map of Lexicon IDs (NSID@semver) to schema definitions.
 * It is **empty by default**: no Identity, Social, or Trade lexicons are
 * pre-registered. Consumers explicitly register a Standard Library or load
 * Extensions at bootstrap time (see `./engine.ts` and the Standard Library /
 * Extension exports).
 *
 * The class does ZERO validation work itself — it just stores and resolves.
 * Validation is performed by `validateEvent` (see `./engine.ts`) which
 * accepts a registry as a parameter. This decoupling preserves the
 * Box-vs-Content separation: the registry (Box) never knows about any
 * specific domain (Content).
 */

import type { Schema } from "./schema";
import { compareSemver, isForwardCompatible, parseLexiconId, type Semver } from "./semver";

/** A single lexicon definition held in the registry. */
export interface LexiconDef {
  /** Full Lexicon ID — e.g., "kash.id.profile@1.0.0". */
  readonly id: string;
  /** NSID portion — e.g., "kash.id.profile". */
  readonly nsid: string;
  /** Semver of this definition. */
  readonly semver: Semver;
  /** Schema for the envelope body. */
  readonly bodySchema: Schema;
  /** Optional human-readable title (shown by tooling). */
  readonly title?: string;
  /** Optional human-readable description (shown by tooling). */
  readonly description?: string;
}

/** Options accepted by the `register(id, schema, opts)` convenience overload. */
export interface RegisterOptions {
  readonly title?: string;
  readonly description?: string;
}

/**
 * In-memory map of registered lexicons.
 *
 * Multiple major versions for the same NSID may co-exist. The registry
 * resolves by exact match first, then by forward-compatible major.
 */
export class LexiconRegistry {
  private readonly byId: Map<string, LexiconDef> = new Map();
  private readonly byNsid: Map<string, LexiconDef[]> = new Map();

  /** Number of registered definitions. */
  get size(): number {
    return this.byId.size;
  }

  /** Register a fully-described lexicon entry. */
  register(entry: LexiconDef): this;
  /** Register by Lexicon ID + body schema (convenience overload). */
  register(id: string, bodySchema: Schema, opts?: RegisterOptions): this;
  register(arg1: LexiconDef | string, arg2?: Schema, arg3?: RegisterOptions): this {
    if (typeof arg1 === "string") {
      if (arg2 === undefined) {
        throw new TypeError("LexiconRegistry.register(id, schema): schema is required");
      }
      const parsed = parseLexiconId(arg1);
      if (parsed === null) {
        throw new TypeError(`LexiconRegistry.register: invalid lexicon ID "${arg1}"`);
      }
      const entry: LexiconDef = {
        id: arg1,
        nsid: parsed.nsid,
        semver: parsed.semver,
        bodySchema: arg2,
        ...(arg3?.title !== undefined ? { title: arg3.title } : {}),
        ...(arg3?.description !== undefined ? { description: arg3.description } : {}),
      };
      return this.addEntry(entry);
    }
    return this.addEntry(arg1);
  }

  /** Register a batch of entries (typically a Standard Library or Extension export). */
  registerAll(entries: readonly LexiconDef[]): this {
    for (const entry of entries) this.addEntry(entry);
    return this;
  }

  /** Exact-match lookup by full Lexicon ID. Returns undefined when not present. */
  get(id: string): LexiconDef | undefined {
    return this.byId.get(id);
  }

  /**
   * Forward-compatible lookup by NSID + caller-supplied semver.
   * Returns the highest-version registered entry whose major matches the caller.
   */
  resolve(nsid: string, semver: Semver): LexiconDef | undefined {
    const candidates = this.byNsid.get(nsid);
    if (!candidates) return undefined;
    for (const def of candidates) {
      if (isForwardCompatible(def.semver, semver)) return def;
    }
    return undefined;
  }

  /** True if any version of the given NSID is registered. */
  has(nsid: string): boolean {
    return this.byNsid.has(nsid);
  }

  /** True if the exact Lexicon ID is registered. */
  hasId(id: string): boolean {
    return this.byId.has(id);
  }

  /** All registered Lexicon IDs, in insertion order. */
  list(): readonly string[] {
    return Array.from(this.byId.keys());
  }

  /** All registered entries. */
  entries(): readonly LexiconDef[] {
    return Array.from(this.byId.values());
  }

  /** All NSIDs present in the registry. */
  namespaces(): readonly string[] {
    return Array.from(this.byNsid.keys());
  }

  /** Drop every registered entry. */
  clear(): void {
    this.byId.clear();
    this.byNsid.clear();
  }

  /** Remove a single entry by its full Lexicon ID. Returns whether anything was removed. */
  unregister(id: string): boolean {
    const entry = this.byId.get(id);
    if (!entry) return false;
    this.byId.delete(id);
    const list = this.byNsid.get(entry.nsid);
    if (list) {
      const next = list.filter((e) => e.id !== id);
      if (next.length === 0) this.byNsid.delete(entry.nsid);
      else this.byNsid.set(entry.nsid, next);
    }
    return true;
  }

  /* ── internal ─────────────────────────────────────────────────── */

  private addEntry(entry: LexiconDef): this {
    this.byId.set(entry.id, entry);
    const list = this.byNsid.get(entry.nsid);
    if (list) {
      // remove any existing entry with the same full ID, then re-insert sorted descending
      const next = list.filter((e) => e.id !== entry.id);
      next.push(entry);
      next.sort((a, b) => compareSemver(b.semver, a.semver));
      this.byNsid.set(entry.nsid, next);
    } else {
      this.byNsid.set(entry.nsid, [entry]);
    }
    return this;
  }
}
