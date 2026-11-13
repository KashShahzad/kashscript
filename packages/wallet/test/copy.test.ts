import { describe, expect, test } from "bun:test";
import { DEFAULT_COPY, copyWith, fill } from "../src/copy";
import { ERROR_MESSAGES } from "../src/errors";
import { BANNED_WORDS } from "../src/headless";

describe("the words — d44's test, and the design language's wallet list", () => {
  test("no default string or error message names the ecosystem, a member or a program, or a word a person must learn", () => {
    const all = [...Object.entries(DEFAULT_COPY), ...Object.entries(ERROR_MESSAGES)];
    const hits = all.filter(([, s]) => BANNED_WORDS.test(s)).map(([k, s]) => `${k}: ${s}`);
    expect(hits).toEqual([]);
  });

  test("the list catches what it should, and not what it shouldn't", () => {
    for (const bad of ["Indorania", "the proof economy", "your standing", "KashScript", "Indusland", "Duedale", "Oreoasis", "Tehzeeb", "Kumak", "Industown", "presence", "flow", "process", "predicate", "credential"]) {
      expect({ bad, caught: BANNED_WORDS.test(bad) }).toEqual({ bad, caught: true });
    }
    for (const fine of ["processing is not in our copy", "a workflow", "outstanding"]) {
      expect({ fine, caught: BANNED_WORDS.test(fine) }).toEqual({ fine, caught: false });
    }
  });

  test("placeholders fill, and a missing value stays visible rather than guessed", () => {
    expect(fill(DEFAULT_COPY.askDeclineCosts, { goodFor: "a free pot of tea" })).toBe("Saying no costs only this: a free pot of tea");
    expect(fill("{a} and {b}", { a: "x" })).toBe("x and {b}");
    expect(copyWith({ unlockPrompt: "Open" }).unlockPrompt).toBe("Open");
  });

  test("every state has words, not only a mark", () => {
    for (const key of ["checkSignedByBoth", "checkOneSignature", "checkDoesntMatch", "checkExpired", "checkPractice", "checkUnlisted"] as const) {
      expect(DEFAULT_COPY[key].length).toBeGreaterThan(5);
    }
  });
});
