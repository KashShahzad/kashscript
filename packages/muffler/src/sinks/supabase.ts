// Supabase RecordSink — projects indexed records into a venture's read models.
//
// The seed (@indus/muffler) hardcoded the `rm_*` table map + per-collection
// row projections. Here the projection is INJECTED via `SupabaseSinkConfig`:
// this class owns only the generic Supabase `.from().upsert/delete/select`
// mechanics, while the venture supplies its table names + `toRow` + identity
// columns. That keeps the "Supabase schema" + "rm_* projections" venture-side
// (ADR-0016 guard b) while the adapter ships generically.
//
// Subpath-only export (`@kashscript/muffler/sink-supabase`) so the main barrel
// never imports the `@supabase/supabase-js` peer dependency. The import below
// is type-only (erased at emit).

import type { SupabaseClient } from "@supabase/supabase-js";
import type { IndexedRecord, RecordKey, RecordSink } from "../indexer";

/** The venture-supplied projection: how indexed records map onto its tables. */
export interface SupabaseSinkConfig {
  /** Table for a collection, or null to skip records of that collection. */
  tableFor(collection: string): string | null;
  /** Project an indexed record into a table row. */
  toRow(record: IndexedRecord): Record<string, unknown>;
  /** The upsert `onConflict` columns for a collection (e.g. "did" or "did,rkey").
   *  If it includes "rkey", `remove` filters by rkey too. */
  onConflictFor(collection: string): string;
  /** Every table `purgeRepo` must clear for a deactivated repo. */
  allTables: readonly string[];
  /** Cursor-state table (default "muffler_sync_state"). */
  cursorTable?: string;
  /** Cursor-state row id (default "firehose"). */
  cursorId?: string;
}

export class SupabaseRecordSink implements RecordSink {
  private readonly cursorTable: string;
  private readonly cursorId: string;

  constructor(
    private readonly db: SupabaseClient,
    private readonly config: SupabaseSinkConfig,
  ) {
    this.cursorTable = config.cursorTable ?? "muffler_sync_state";
    this.cursorId = config.cursorId ?? "firehose";
  }

  async upsert(record: IndexedRecord): Promise<void> {
    const table = this.config.tableFor(record.collection);
    if (table === null) return;
    const { error } = await this.db
      .from(table)
      .upsert(this.config.toRow(record), { onConflict: this.config.onConflictFor(record.collection) });
    if (error) throw new Error(`muffler sink upsert ${table}: ${error.message}`);
  }

  async remove(key: RecordKey): Promise<void> {
    const table = this.config.tableFor(key.collection);
    if (table === null) return;
    let q = this.db.from(table).delete().eq("did", key.did);
    if (this.config.onConflictFor(key.collection).includes("rkey")) {
      q = q.eq("rkey", key.rkey);
    }
    const { error } = await q;
    if (error) throw new Error(`muffler sink remove ${table}: ${error.message}`);
  }

  async purgeRepo(did: string): Promise<void> {
    for (const table of this.config.allTables) {
      const { error } = await this.db.from(table).delete().eq("did", did);
      if (error) throw new Error(`muffler sink purge ${table}: ${error.message}`);
    }
  }

  async loadCursor(): Promise<number | null> {
    const { data, error } = await this.db
      .from(this.cursorTable)
      .select("seq")
      .eq("id", this.cursorId)
      .maybeSingle();
    if (error) throw new Error(`muffler sink loadCursor: ${error.message}`);
    const seq = (data as { seq?: unknown } | null)?.seq;
    return seq != null ? Number(seq) : null;
  }

  async saveCursor(seq: number): Promise<void> {
    const { error } = await this.db
      .from(this.cursorTable)
      .upsert({ id: this.cursorId, seq, updated_at: new Date().toISOString() }, { onConflict: "id" });
    if (error) throw new Error(`muffler sink saveCursor: ${error.message}`);
  }
}
