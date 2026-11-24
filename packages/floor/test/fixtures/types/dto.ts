import type { FloorCount } from "@kashscript/floor";

export interface ShownCount {
  readonly count: FloorCount;
  readonly label: string;
}

interface Base {
  readonly k: number;
}

export interface Visits extends Base {
  readonly months: readonly ShownCount[];
  readonly byDoor: Readonly<Record<string, ShownCount>>;
  readonly note: string | null;
}

export type Picked = Pick<Visits, "note" | "months">;
export type Omitted = Omit<Visits, "k">;
