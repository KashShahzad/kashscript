// An establishment's book (Oreoasis's OS-3, OS-3b): its three DSSE payload types are registered, as DSSE types, and
// nothing that was registered before changed. The row they ride in keeps the ledger's own tag (d99(d)).
import { describe, expect, it } from "bun:test";

import { DST_REGISTRY, isRegisteredDst, lookupDst } from "../src/dst";

const BOOK_TYPES = ["application/vnd.kash.book-entry+json", "application/vnd.kash.book-export-request+json", "application/vnd.kash.seat-export+json"] as const;

describe("the establishment book's types", () => {
  it("are registered, as DSSE payload types owned by Oreoasis, and live", () => {
    for (const tag of BOOK_TYPES) {
      expect(isRegisteredDst(tag)).toBe(true);
      const e = lookupDst(tag)!;
      expect(e.family).toBe("dsse-type");
      expect(e.owner).toBe("oreoasis");
      expect(e.reserved).toBeUndefined();
    }
  });

  it("ride in a row whose tag is the ledger's own, unchanged", () => {
    expect(lookupDst("oreoasis-ledger-v1\n")?.family).toBe("kash-event");
  });

  it("are each registered once, and no tag appears twice in the registry", () => {
    const tags = DST_REGISTRY.map((e) => e.tag);
    expect(new Set(tags).size).toBe(tags.length);
    for (const tag of BOOK_TYPES) expect(tags.filter((t) => t === tag)).toHaveLength(1);
  });

  it("name no product in the tag itself", () => {
    for (const tag of BOOK_TYPES) expect(/oreoasis|duedale|indusland|indorania/i.test(tag)).toBe(false);
  });
});
