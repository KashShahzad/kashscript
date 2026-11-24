/** A plan's limit on live keys: counted on the server, never shown to anyone. */
export async function liveKeys(db: { key: { count(q: unknown): Promise<number> } }, orgId: string): Promise<number> {
  return db.key.count({ where: { orgId } });
}
