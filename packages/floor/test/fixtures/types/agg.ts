import type { Omitted, Picked, Visits } from "./dto.js";
import type { External } from "some-package";

export async function visits(): Promise<Visits> {
  return null as never;
}

export const picked = (): Picked => null as never;

export function omitted(): Omitted {
  return null as never;
}

export function external(): { readonly e: External } {
  return null as never;
}

function local(): Visits {
  return null as never;
}

export { local as renamed };
