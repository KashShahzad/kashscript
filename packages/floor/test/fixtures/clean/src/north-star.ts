import { suppress, suppressSeries, type FloorCount, type FloorTotal } from "@kashscript/floor";

/** One organisation's week: its own receipts (each in its book), and counts of others' acts, suppressed. */
export interface OrgWeek {
  readonly week: string;
  readonly receiptsSignedByOthers: number;
  readonly proofPagesOpened: FloorCount;
  readonly decisions: { readonly months: readonly FloorCount[]; readonly total: FloorTotal };
}

export async function orgWeeks(rows: readonly { week: string; own: number; opens: number; decided: number[] }[]): Promise<OrgWeek[]> {
  return rows.map((r) => {
    const series = suppressSeries(r.decided);
    return { week: r.week, receiptsSignedByOthers: r.own, proofPagesOpened: suppress(r.opens), decisions: { months: series.cells, total: series.total } };
  });
}
