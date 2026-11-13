// Money discipline: every amount is an INTEGER number of minor units (paisa).
// No floating-point arithmetic ever touches a mandate amount. Ported from the
// duedale-core/money seed.

import { WhiffinPolicyError } from "./errors";

/** An integer number of minor currency units (e.g. PKR paisa). */
export type Cents = number;

/** Asserts a strictly-positive integer amount, else throws WhiffinPolicyError. */
export function assertPositivePaisa(amount: Cents): void {
  if (!Number.isInteger(amount) || amount <= 0) {
    throw new WhiffinPolicyError("VALIDATION", `amountPaisa must be a positive integer, got ${String(amount)}`);
  }
}
