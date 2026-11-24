export async function receiptsFor(db: { receipt: { count(): Promise<number> } }) {
  return db.receipt.count();
}
