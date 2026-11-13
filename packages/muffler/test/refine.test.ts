import { describe, it, expect } from "bun:test";
import { RefineError, createLexiconRefiner } from "../src/refine";
import { EXAMPLE, collectionToLexiconId, exampleRefiner, exampleRegistry } from "./example-lexicons";

describe("createLexiconRefiner", () => {
  it("validates, JCS-canonicalizes, and content-addresses a good record", async () => {
    const refiner = exampleRefiner();
    expect(refiner.handles(EXAMPLE.experience)).toBe(true);
    expect(refiner.handles("com.other.thing")).toBe(false);

    const refined = await refiner.refine(EXAMPLE.experience, { title: "T", subcategories: ["x"] });
    // RFC 8785 canonical form sorts object keys.
    expect(refined.canonical).toBe('{"subcategories":["x"],"title":"T"}');
    expect(refined.cid.startsWith("b")).toBe(true);
    // Deterministic content addressing.
    const again = await refiner.refine(EXAMPLE.experience, { title: "T", subcategories: ["x"] });
    expect(again.cid).toBe(refined.cid);
  });

  it("throws RefineError(INVALID_RECORD) on a record that fails lexicon validation", async () => {
    const refiner = exampleRefiner();
    await expect(refiner.refine(EXAMPLE.experience, { title: "no subs" })).rejects.toBeInstanceOf(RefineError);
    await expect(refiner.refine(EXAMPLE.experience, { title: "no subs" })).rejects.toMatchObject({
      code: "INVALID_RECORD",
    });
  });

  it("throws RefineError(UNKNOWN_COLLECTION) for an unhandled collection", async () => {
    const refiner = exampleRefiner();
    await expect(refiner.refine("com.other.thing", {})).rejects.toMatchObject({ code: "UNKNOWN_COLLECTION" });
  });

  it("runs the postValidate hook (generalized attribute validation)", async () => {
    const refiner = createLexiconRefiner({
      registry: exampleRegistry(),
      collectionToLexiconId,
      postValidate: (_collection, value) => {
        if ((value as { title?: unknown }).title === "BANNED") {
          throw new RefineError("INVALID_ATTRIBUTES", "banned title");
        }
      },
    });
    await expect(
      refiner.refine(EXAMPLE.experience, { title: "BANNED", subcategories: ["x"] }),
    ).rejects.toMatchObject({ code: "INVALID_ATTRIBUTES" });
    // A non-banned record still refines.
    const ok = await refiner.refine(EXAMPLE.experience, { title: "fine", subcategories: ["x"] });
    expect(ok.cid.startsWith("b")).toBe(true);
  });
});
