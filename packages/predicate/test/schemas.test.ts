import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { getSchemaDefinition } from "@kashscript/lexicons/engine";
import { LexiconRegistry } from "@kashscript/lexicons/registry";
import { KASH_DECISION_ID, KASH_DECISION_LEXICON } from "../src/decision-schema";

const SPECS = join(import.meta.dir, "..", "..", "..", "specs", "schemas");

describe("the decision's published JSON Schema stays in step with predicate (its home since KS-Q1b)", () => {
  test("decision.schema.json", () => {
    const generated = getSchemaDefinition(KASH_DECISION_ID, new LexiconRegistry().register(KASH_DECISION_LEXICON));
    const published = JSON.parse(readFileSync(join(SPECS, "decision.schema.json"), "utf8"));
    expect(published).toEqual(JSON.parse(JSON.stringify(generated)));
  });
  test("the decision is not a public record — lexicons no longer carries it (d59)", async () => {
    const door = await import("@kashscript/lexicons/extensions/door");
    expect(Object.keys(door).filter((k) => k.includes("DECISION_BODY") || k.includes("DECISION_LEXICON") || k === "PERSONAL_LEXICONS")).toEqual([]);
    expect(door.DOOR_LEXICONS.map((l) => l.id)).toEqual(["kash.rule@1.0.0", "kash.rule@1.1.0", "kash.rule@1.2.0", "kash.adoption@1.0.0"]);
  });
});
