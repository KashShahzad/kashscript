import { FLOOR_K, suppress } from "@kashscript/floor";

const K = 4;

export function lowK(n: number) {
  return suppress(n, 3);
}

export function varK(n: number) {
  return suppress(n, K);
}

export function okK(n: number) {
  return suppress(n, FLOOR_K) ?? suppress(n, 7);
}
