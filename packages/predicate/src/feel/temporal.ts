/**
 * FEEL's temporal values in the subset: `date`, `date and time` (always with
 * an offset or `Z` — never local, never a zone id, so every platform agrees
 * without a time-zone database), and the two durations.
 *
 * The calendar is the proleptic Gregorian one (XML Schema, which DMN cites).
 * Month arithmetic clamps to the month's end: 2026-03-31 − P1M = 2026-02-28.
 */

const NS_PER_SEC = 1_000_000_000n;
const NS_PER_DAY = 86_400n * NS_PER_SEC;

export interface FeelDate {
  readonly kind: "date";
  readonly year: number;
  readonly month: number;
  readonly day: number;
}

export interface FeelDateTime {
  readonly kind: "date and time";
  readonly year: number;
  readonly month: number;
  readonly day: number;
  readonly hour: number;
  readonly minute: number;
  readonly second: number;
  readonly nanos: number;
  /** Minutes east of UTC. */
  readonly offsetMinutes: number;
}

export interface DaysTimeDuration {
  readonly kind: "days and time duration";
  readonly nanos: bigint;
}

export interface YearsMonthsDuration {
  readonly kind: "years and months duration";
  readonly months: number;
}

export type Temporal = FeelDate | FeelDateTime | DaysTimeDuration | YearsMonthsDuration;

const isLeap = (y: number): boolean => (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;

export function daysInMonth(y: number, m: number): number {
  return [31, isLeap(y) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1]!;
}

const YEAR_MAX = 999_999_999;

/** Days since 1970-01-01 for a civil date (H. Hinnant's algorithm; exact for any year here). */
export function epochDay(y: number, m: number, d: number): number {
  const yy = m <= 2 ? y - 1 : y;
  const era = Math.floor(yy / 400);
  const yoe = yy - era * 400;
  const mp = (m + 9) % 12;
  const doy = Math.floor((153 * mp + 2) / 5) + d - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return era * 146_097 + doe - 719_468;
}

export function civilFromEpochDay(z0: number): { year: number; month: number; day: number } {
  const z = z0 + 719_468;
  const era = Math.floor(z / 146_097);
  const doe = z - era * 146_097;
  const yoe = Math.floor((doe - Math.floor(doe / 1460) + Math.floor(doe / 36_524) - Math.floor(doe / 146_096)) / 365);
  const doy = doe - (365 * yoe + Math.floor(yoe / 4) - Math.floor(yoe / 100));
  const mp = Math.floor((5 * doy + 2) / 153);
  const day = doy - Math.floor((153 * mp + 2) / 5) + 1;
  const month = mp < 10 ? mp + 3 : mp - 9;
  return { year: yoe + era * 400 + (month <= 2 ? 1 : 0), month, day };
}

function validDate(y: number, m: number, d: number): boolean {
  return Number.isInteger(y) && Math.abs(y) <= YEAR_MAX && m >= 1 && m <= 12 && d >= 1 && d <= daysInMonth(y, m);
}

export function makeDate(year: number, month: number, day: number): FeelDate | null {
  return validDate(year, month, day) ? { kind: "date", year, month, day } : null;
}

const DATE_RE = /^(-?\d{4,9})-(\d{2})-(\d{2})$/;
const DT_RE = /^(-?\d{4,9})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/;
/** A date-time string with no offset, or with a zone id — outside the subset. */
export const LOCAL_OR_ZONED_DT_RE = /^-?\d{4,9}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:@.+)?$/;

export function parseDate(text: string): FeelDate | null {
  const m = DATE_RE.exec(text);
  if (m === null) return null;
  const y = Number(m[1]);
  if (m[1]!.replace("-", "").length > 4 && m[1]!.replace("-", "").startsWith("0")) return null;
  return makeDate(y, Number(m[2]), Number(m[3]));
}

export function parseDateTime(text: string): FeelDateTime | null {
  const m = DT_RE.exec(text);
  if (m === null) return null;
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const hour = Number(m[4]);
  const minute = Number(m[5]);
  const second = Number(m[6]);
  if (!validDate(year, month, day) || hour > 23 || minute > 59 || second > 59) return null;
  const nanos = m[7] !== undefined ? Number(m[7].padEnd(9, "0")) : 0;
  let offsetMinutes = 0;
  if (m[8] !== "Z") {
    const sign = m[8]!.startsWith("-") ? -1 : 1;
    const oh = Number(m[8]!.slice(1, 3));
    const om = Number(m[8]!.slice(4, 6));
    if (oh > 14 || om > 59 || (oh === 14 && om > 0)) return null;
    offsetMinutes = sign * (oh * 60 + om);
  }
  return { kind: "date and time", year, month, day, hour, minute, second, nanos, offsetMinutes };
}

/** Nanoseconds since the epoch, UTC. */
export function instantOf(dt: FeelDateTime): bigint {
  const local =
    BigInt(epochDay(dt.year, dt.month, dt.day)) * NS_PER_DAY +
    BigInt(dt.hour * 3600 + dt.minute * 60 + dt.second) * NS_PER_SEC +
    BigInt(dt.nanos);
  return local - BigInt(dt.offsetMinutes) * 60n * NS_PER_SEC;
}

function floorDiv(a: bigint, b: bigint): bigint {
  const q = a / b;
  return (a % b !== 0n && (a < 0n) !== (b < 0n)) ? q - 1n : q;
}

export function dateTimeFromInstant(instant: bigint, offsetMinutes: number): FeelDateTime | null {
  const local = instant + BigInt(offsetMinutes) * 60n * NS_PER_SEC;
  const day = floorDiv(local, NS_PER_DAY);
  const within = local - day * NS_PER_DAY;
  const civil = civilFromEpochDay(Number(day));
  if (Math.abs(civil.year) > YEAR_MAX) return null;
  const secs = Number(within / NS_PER_SEC);
  return {
    kind: "date and time",
    ...civil,
    hour: Math.floor(secs / 3600),
    minute: Math.floor((secs % 3600) / 60),
    second: secs % 60,
    nanos: Number(within % NS_PER_SEC),
    offsetMinutes,
  };
}

/* ── durations ─────────────────────────────────────────────────────────── */

const DUR_RE = /^(-)?P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)(?:\.(\d{0,9}))?S)?)?$/;

/** An ISO 8601 duration: years-and-months, or days-and-time. A mix of both, or an empty `P`, is null. */
export function parseDuration(text: string): DaysTimeDuration | YearsMonthsDuration | null {
  const m = DUR_RE.exec(text);
  if (m === null) return null;
  const [, neg, y, mo, d, h, mi, s, frac] = m;
  if (text.endsWith("T") || text === "P" || text === "-P") return null;
  const hasYM = y !== undefined || mo !== undefined;
  const hasDT = d !== undefined || h !== undefined || mi !== undefined || s !== undefined;
  if (!hasYM && !hasDT) return null;
  if (hasYM && hasDT) return null;
  const sign = neg === "-" ? -1 : 1;
  if (hasYM) {
    const months = Number(y ?? 0) * 12 + Number(mo ?? 0);
    if (!Number.isSafeInteger(months)) return null;
    return ymDuration(sign * months);
  }
  const nanos =
    BigInt(d ?? 0) * NS_PER_DAY +
    BigInt(h ?? 0) * 3600n * NS_PER_SEC +
    BigInt(mi ?? 0) * 60n * NS_PER_SEC +
    BigInt(s ?? 0) * NS_PER_SEC +
    BigInt((frac ?? "").padEnd(9, "0") || "0");
  return dtDuration(sign < 0 ? -nanos : nanos);
}

export function dtDuration(nanos: bigint): DaysTimeDuration {
  return { kind: "days and time duration", nanos: nanos === -0n ? 0n : nanos };
}

export function ymDuration(months: number): YearsMonthsDuration {
  return { kind: "years and months duration", months: months === 0 ? 0 : months };
}

/* ── arithmetic ────────────────────────────────────────────────────────── */

export function addMonthsToCivil(y: number, m: number, d: number, months: number): { year: number; month: number; day: number } | null {
  const total = y * 12 + (m - 1) + months;
  const year = Math.floor(total / 12);
  const month = total - year * 12 + 1;
  if (Math.abs(year) > YEAR_MAX) return null;
  return { year, month, day: Math.min(d, daysInMonth(year, month)) };
}

export function dateAddMonths(date: FeelDate, months: number): FeelDate | null {
  const c = addMonthsToCivil(date.year, date.month, date.day, months);
  return c === null ? null : { kind: "date", ...c };
}

export function dateTimeAddMonths(dt: FeelDateTime, months: number): FeelDateTime | null {
  const c = addMonthsToCivil(dt.year, dt.month, dt.day, months);
  return c === null ? null : { ...dt, ...c };
}

export function dateAddNanos(date: FeelDate, nanos: bigint): FeelDate | null {
  const local = BigInt(epochDay(date.year, date.month, date.day)) * NS_PER_DAY + nanos;
  const civil = civilFromEpochDay(Number(floorDiv(local, NS_PER_DAY)));
  return makeDate(civil.year, civil.month, civil.day);
}

export function dateTimeAddNanos(dt: FeelDateTime, nanos: bigint): FeelDateTime | null {
  return dateTimeFromInstant(instantOf(dt) + nanos, dt.offsetMinutes);
}

export function dateMinusDate(a: FeelDate, b: FeelDate): DaysTimeDuration {
  return dtDuration(BigInt(epochDay(a.year, a.month, a.day) - epochDay(b.year, b.month, b.day)) * NS_PER_DAY);
}

export function dateTimeMinus(a: FeelDateTime, b: FeelDateTime): DaysTimeDuration {
  return dtDuration(instantOf(a) - instantOf(b));
}

/** `years and months duration(from, to)`: whole months from `from` to `to`, truncated toward zero. */
export function monthsBetween(
  from: { year: number; month: number; day: number; rest?: bigint },
  to: { year: number; month: number; day: number; rest?: bigint },
): YearsMonthsDuration {
  let months = (to.year * 12 + to.month) - (from.year * 12 + from.month);
  const toTail = [to.day, to.rest ?? 0n] as const;
  const fromTail = [from.day, from.rest ?? 0n] as const;
  const tailLess = (a: readonly [number, bigint], b: readonly [number, bigint]): boolean => a[0] < b[0] || (a[0] === b[0] && a[1] < b[1]);
  if (months > 0 && tailLess(toTail, fromTail)) months -= 1;
  else if (months < 0 && tailLess(fromTail, toTail)) months += 1;
  return ymDuration(months);
}

/** Nanoseconds into the local day — the tail compared after the day of month. */
export function localNanosOfDay(dt: FeelDateTime): bigint {
  return BigInt(dt.hour * 3600 + dt.minute * 60 + dt.second) * NS_PER_SEC + BigInt(dt.nanos);
}

export const NANOS_PER_DAY = NS_PER_DAY;
export const NANOS_PER_SECOND = NS_PER_SEC;

/* ── display (tests and messages only) ─────────────────────────────────── */

const pad = (n: number, w = 2): string => String(Math.abs(n)).padStart(w, "0");

export function formatDate(d: { year: number; month: number; day: number }): string {
  return `${d.year < 0 ? "-" : ""}${pad(d.year, 4)}-${pad(d.month)}-${pad(d.day)}`;
}

export function formatTemporal(t: Temporal): string {
  switch (t.kind) {
    case "date":
      return formatDate(t);
    case "date and time": {
      const frac = t.nanos === 0 ? "" : `.${String(t.nanos).padStart(9, "0").replace(/0+$/, "")}`;
      const off = t.offsetMinutes === 0 ? "Z" : `${t.offsetMinutes < 0 ? "-" : "+"}${pad(Math.floor(Math.abs(t.offsetMinutes) / 60))}:${pad(Math.abs(t.offsetMinutes) % 60)}`;
      return `${formatDate(t)}T${pad(t.hour)}:${pad(t.minute)}:${pad(t.second)}${frac}${off}`;
    }
    case "years and months duration": {
      const abs = Math.abs(t.months);
      const y = Math.floor(abs / 12);
      const m = abs % 12;
      return `${t.months < 0 ? "-" : ""}P${y > 0 ? `${y}Y` : ""}${m > 0 || y === 0 ? `${m}M` : ""}`;
    }
    case "days and time duration": {
      let n = t.nanos < 0n ? -t.nanos : t.nanos;
      const days = n / NS_PER_DAY;
      n -= days * NS_PER_DAY;
      const secsTotal = n / NS_PER_SEC;
      const nanos = n % NS_PER_SEC;
      const h = secsTotal / 3600n;
      const mi = (secsTotal % 3600n) / 60n;
      const s = secsTotal % 60n;
      let time = "";
      if (h > 0n) time += `${h}H`;
      if (mi > 0n) time += `${mi}M`;
      if (s > 0n || nanos > 0n) time += `${s}${nanos > 0n ? `.${nanos.toString().padStart(9, "0").replace(/0+$/, "")}` : ""}S`;
      const body = `${days > 0n ? `${days}D` : ""}${time !== "" ? `T${time}` : ""}`;
      return `${t.nanos < 0n ? "-" : ""}P${body === "" ? "T0S" : body}`;
    }
  }
}
