import { describe, expect, test } from "bun:test";
import { checkFeel, Decimal, evaluateFeel, FeelContext, fromJson, inSubset, parseDate, parseDateTime, show, T, type FeelValue } from "../src/feel";
import { runAll } from "./tck/run";

const ev = (src: string, vars: Record<string, FeelValue> = {}): FeelValue => evaluateFeel(src, vars).value;
const num = (s: string): Decimal => Decimal.parse(s)!;

describe("the DMN TCK — subset or refuse, never wrong", () => {
  const r = runAll();
  test(`every case it accepts answers as the TCK expects (commit ${r.file.commit.slice(0, 7)})`, () => {
    const wrong = r.wrong.map((v) => (v.kind === "wrong" ? `${v.c.folder} ${v.c.id}: ${v.c.expression} → ${v.got}, want ${v.want}` : ""));
    expect(wrong).toEqual([]);
  });
  test("the claimed count does not fall (867 of 1,873 at the pinned commit)", () => {
    expect(r.pass.length).toBeGreaterThanOrEqual(867);
    expect(r.pass.length + r.refused.length).toBe(r.file.cases.length);
  });
});

describe("numbers are exact decimals", () => {
  test("money does not drift", () => {
    expect(show(ev("0.1 + 0.2"))).toBe("0.3");
    expect(show(ev("sum([1500.50, 1499.50, 0.01])"))).toBe("3000.01");
  });
  test("division rounds to 34 significant digits, half to even", () => {
    expect(show(ev("1 / 3"))).toBe("0.3333333333333333333333333333333333");
    expect(show(ev("2 / 3"))).toBe("0.6666666666666666666666666666666667");
    expect(ev("1 / 0")).toBeNull();
  });
  test("a JSON number becomes its shortest decimal, never its binary expansion", () => {
    expect(show(fromJson(0.1, "number"))).toBe("0.1");
    expect(fromJson("12.5", "number")).toEqual(num("12.5"));
    expect(fromJson("12,5", "number")).toBeNull();
  });
});

describe("dates and durations", () => {
  const asOf = parseDateTime("2026-10-28T09:00:00Z")!;
  test("month arithmetic clamps to the month's end", () => {
    expect(show(ev('date("2026-03-31") - duration("P1M")'))).toBe("2026-02-28");
    expect(show(ev('date("2024-03-31") - duration("P1M")'))).toBe("2024-02-29");
    expect(show(ev('asOf - duration("P24M")', { asOf }))).toBe("2024-10-28T09:00:00Z");
  });
  test("a duration multiplies by a number", () => {
    expect(show(ev('3 * duration("P1M")'))).toBe("P3M");
    expect(show(ev('duration("P1D") * 28'))).toBe("P28D");
  });
  test("date(asOf) converts, so a date claim compares with the evaluation time", () => {
    expect(ev('date("2026-11-20") <= date(asOf) + duration("P28D")', { asOf })).toBe(true);
    expect(ev('date("2026-11-30") <= date(asOf) + duration("P28D")', { asOf })).toBe(false);
  });
  test("comparing a date with a date and time is null, and the check says so before it runs", () => {
    expect(ev('date("2026-10-28") < asOf', { asOf })).toBeNull();
    const c = checkFeel('d < asOf', { d: T.date, asOf: T.dateTime });
    expect(c.ok).toBe(false);
    expect(c.problems[0]!.message).toContain("date(asOf)");
  });
  test("local and zoned date-times are refused by name; an offset or Z is in", () => {
    expect(inSubset('date and time("2026-10-28T09:00:00")')).toBe(false);
    expect(inSubset('@"2026-10-28T09:00:00@Asia/Karachi"')).toBe(false);
    expect(inSubset('date and time("2026-10-28T09:00:00+05:00")')).toBe(true);
    expect(parseDate("2026-02-29")).toBeNull();
  });
});

describe("lists, filters and quantifiers", () => {
  const projects: FeelValue = [
    FeelContext.from({ acceptedAt: parseDateTime("2026-01-10T00:00:00Z"), skills: ["React", "TypeScript"] }),
    FeelContext.from({ acceptedAt: parseDateTime("2025-06-01T00:00:00Z"), skills: ["Go"] }),
    FeelContext.from({ acceptedAt: parseDateTime("2023-01-01T00:00:00Z"), skills: ["React"] }),
  ];
  const asOf = parseDateTime("2026-10-28T09:00:00Z")!;
  test("a filter reads each item's fields; a path over a list projects", () => {
    expect(show(ev('count(receipts[acceptedAt >= asOf - duration("P24M")])', { receipts: projects, asOf }))).toBe("2");
    expect(show(ev("distinct values(flatten)", { flatten: ["a", "b", "a"] }))).toBe('["a", "b"]');
    expect(show(ev("receipts.skills[1]", { receipts: projects }))).toBe('["React", "TypeScript"]');
  });
  test("some and every", () => {
    expect(ev('some p in receipts[acceptedAt >= asOf - duration("P24M")] satisfies list contains(p.skills, "React")', { receipts: projects, asOf })).toBe(true);
    expect(ev('every p in receipts satisfies list contains(p.skills, "React")', { receipts: projects })).toBe(false);
    expect(ev("every p in [] satisfies p > 1")).toBe(true);
    expect(ev("some p in [] satisfies p > 1")).toBe(false);
  });
  test("in, with a list of values and an interval", () => {
    expect(ev('"B2" in ("B2", "C1", "C2")')).toBe(true);
    expect(ev("5 in [1..5]")).toBe(true);
    expect(ev("5 in [1..5)")).toBe(false);
  });
  test("three-valued logic", () => {
    expect(ev("true and null")).toBeNull();
    expect(ev("false and null")).toBe(false);
    expect(ev("true or null")).toBe(true);
  });
});

describe("the static check", () => {
  const names = { receipts: T.list(T.context({ acceptedAt: T.dateTime, skills: T.list(T.string), issuer: T.string })), asOf: T.dateTime, minProjects: T.number };
  test("a condition is yes or no — a number is refused, so a condition is never a score", () => {
    const c = checkFeel("count(receipts)", names);
    expect(c.ok).toBe(false);
    expect(c.problems[0]!.message).toContain("never a number or a score");
  });
  test("every name is bound", () => {
    const c = checkFeel("count(receipts) >= minimum", names);
    expect(c.ok).toBe(false);
    expect(c.problems[0]!.message).toContain('"minimum" is not bound');
  });
  test("it reports what it reads: top-level names and claim fields", () => {
    const c = checkFeel('count(receipts[acceptedAt >= asOf - duration("P24M")]) >= minProjects and some p in receipts satisfies list contains(p.skills, "React")', names);
    expect(c.ok).toBe(true);
    expect(new Set(c.names)).toEqual(new Set(["receipts", "asOf", "minProjects"]));
    expect(new Set(c.fields)).toEqual(new Set(["acceptedAt", "skills"]));
  });
  test("what FEEL has and the subset does not is refused by name", () => {
    for (const [src, word] of [
      ["for x in [1] return x", "for"],
      ["if true then 1 else 2", "if"],
      ["today() > asOf", "today"],
      ["now() > asOf", "now"],
      ["mean([1,2]) > 1", "mean"],
      ["{a: 1}.a = 1", "context literals"],
      ["2 ** 3 = 8", "**"],
    ] as const) {
      const c = checkFeel(src, names);
      expect(c.ok).toBe(false);
      expect(c.problems[0]!.outsideSubset).toBe(true);
      expect(c.problems[0]!.message).toContain(word);
    }
  });
  test("a step budget ends a pathological condition with null", () => {
    const big = Array.from({ length: 200 }, (_, i) => Decimal.fromInt(i));
    const r = evaluateFeel("every a in xs, b in xs, c in xs satisfies a + b + c >= 0", { xs: big }, 50_000);
    expect(r.exhausted).toBe(true);
    expect(r.value).toBeNull();
  });
});
