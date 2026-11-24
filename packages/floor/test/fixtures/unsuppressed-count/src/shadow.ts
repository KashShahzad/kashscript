import { suppress } from "@kashscript/floor";

export function sneaky(n: number) {
  const suppress = (x: number) => x;
  return suppress(n);
}

export function honest(n: number) {
  return suppress(n);
}
