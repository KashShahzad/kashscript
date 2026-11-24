import { describe, expect, test } from "bun:test";
import { circular, decisionRefs } from "../src/rules.js";
import { declineKind, forbiddenPrice, isPersonIdentifier, isPersonRef, isSubjectRef, priceNamed, scoreShaped, tokens } from "../src/scan/words.js";

describe("tokens are whole words", () => {
  test("camel, snake, kebab and capitals", () => {
    expect(tokens("trustScore")).toEqual(["trust", "score"]);
    expect(tokens("COMMISSION_RATE_BPS")).toEqual(["commission", "rate", "bps"]);
    expect(tokens("XPValue")).toEqual(["xp", "value"]);
    expect(tokens("not-yet")).toEqual(["not", "yet"]);
  });
});

describe("persons", () => {
  test("a reference names its subject; an actor's column does not", () => {
    expect(isPersonRef("studentDid") && isPersonRef("holder") && isPersonRef("authorDid")).toBe(true);
    expect(isPersonRef("countersignerDid")).toBe(false);
    expect(isSubjectRef("authorDid")).toBe(false);
    expect(isSubjectRef("created_by")).toBe(false);
  });

  test("a person's identifier in a query", () => {
    expect(isPersonIdentifier("guestPhone", "record")).toBe(true);
    expect(isPersonIdentifier("name", "place")).toBe(false);
    expect(isPersonIdentifier("name", "record")).toBe(true);
    expect(isPersonIdentifier("month", "record")).toBe(false);
  });
});

describe("scores", () => {
  test("score, rank, rating, stars, streaks, badges, standing, counts", () => {
    for (const f of ["rating", "stars", "rankPosition", "streakDays", "badges", "standing", "reliability", "kudos", "visitCount", "completionPercent"]) expect(scoreShaped(f, "Member")).toBe(true);
  });

  test("not scores: a start date, a phone number, a money total, a signing grade", () => {
    for (const f of ["startDate", "phoneNumber", "totalPkr", "displayName"]) expect(scoreShaped(f, "Member")).toBe(false);
    expect(scoreShaped("grade", "Acceptance")).toBe(false);
  });
});

describe("declines", () => {
  test("decline, refusal and no-show; never not-yet", () => {
    expect(declineKind("declined")).toBe("decline");
    expect(declineKind("OPTED_OUT")).toBe("decline");
    expect(declineKind("refused")).toBe("refusal");
    expect(declineKind("partial")).toBe("refusal");
    expect(declineKind("noShow")).toBe("no-show");
    expect(declineKind("did_not_come")).toBe("no-show");
    expect(declineKind("not-yet")).toBeUndefined();
    expect(declineKind("accepted")).toBeUndefined();
  });
});

describe("prices", () => {
  test("refused: per record, per check, a fee on verification, any percentage", () => {
    expect(forbiddenPrice("pricePerRecord", false)).toBe("a price per record");
    expect(forbiddenPrice("verificationFee", false)).toBe("a price on verification");
    expect(forbiddenPrice("perThousand", true)).toBe("a price per thousand");
    expect(forbiddenPrice("takeRate", true)).toBe("a percentage");
    expect(forbiddenPrice("markup", false)).toBe("a percentage (markup)");
  });

  test("allowed: an outcome's price, a rate limit, a margin in a layout", () => {
    expect(forbiddenPrice("outcomePrice", true)).toBeUndefined();
    expect(forbiddenPrice("maxPerRequest", false)).toBeUndefined();
    expect(forbiddenPrice("marginTop", false)).toBeUndefined();
    expect(forbiddenPrice("Commissioner", false)).toBeUndefined();
  });

  test("a literal named for a price", () => {
    expect(priceNamed("CHECK_FEE_USD") && priceNamed("DISCOUNT_PCT")).toBe(true);
    expect(priceNamed("yPercent") || priceNamed("SUCCESS_RATE_PCT")).toBe(false);
  });
});

describe("decisions cited by a waiver", () => {
  test("references are read and normalised", () => {
    expect(decisionRefs("d84(c), d96(b), d63(a) and d84 P4.3")).toEqual(["d84(c)", "d96(b)", "d63(a)", "d84p4.3"]);
  });

  test("a waiver citing only its rule's own decisions is circular; a bare number covers its parts", () => {
    expect(circular("price-per-record", "d84(c)")).toBe(true);
    expect(circular("price-per-record", "d84")).toBe(true);
    expect(circular("price-per-record", "d84(c), d63(a)")).toBe(false);
    expect(circular("declined-state", "d84 P3")).toBe(false); // P3 allows a named person's refusal: a waiver may cite it
    expect(circular("declined-state", "d49(a)")).toBe(true);
    expect(circular("person-score", "d64(g)")).toBe(false);
  });
});
