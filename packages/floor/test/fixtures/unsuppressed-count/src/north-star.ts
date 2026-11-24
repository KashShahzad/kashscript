import type { FloorCount } from "@kashscript/floor";

export interface OrgWeek {
  readonly week: string;
  readonly receipts: number;
  readonly opens: FloorCount;
}

export async function orgWeeks(): Promise<OrgWeek[]> {
  return [];
}

export function untyped() {
  return { visits: 3 };
}
