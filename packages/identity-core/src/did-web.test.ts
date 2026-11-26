/**
 * did:web — grammar and resolution-URL derivation (RW-19 branch B; d91(e), d97(h)).
 *
 * One grammar, shared with the published schemas; a deterministic URL per the
 * W3C method; never a fetch (d28).
 */

import { describe, expect, test } from "bun:test";
import { DID_WEB_SOURCE, didWebUrl, isDidWeb, parseDidWeb } from "./did-web";

describe("did:web · grammar", () => {
  test("accepts an organisation on its own domain, with subdomains, a port and colon paths", () => {
    for (const did of [
      "did:web:duedale.com",
      "did:web:indusland.xyz",
      "did:web:acme-inc.sign.duedale.com",
      "did:web:example.com%3A8443",
      "did:web:example.com:u:alice",
      "did:web:localhost",
    ]) {
      expect(isDidWeb(did)).toBe(true);
    }
  });

  test("refuses what the published grammar refuses", () => {
    for (const did of [
      "did:web:",
      "did:web:EXAMPLE.com", // hosts are written lowercase, one spelling per organisation
      "did:web:-example.com",
      "did:web:example.com-",
      "did:web:example.com::double",
      "did:web:example.com:seg/with/slash",
      "did:kash:DnaevFAeTBp7Ht8bShhjcHBZmnZfubu9x4YJJHqB881YpeiX",
      "did:web:example.com:" + "a:".repeat(9).slice(0, -1), // nine path segments
    ]) {
      expect(isDidWeb(did)).toBe(false);
      expect(() => parseDidWeb(did)).toThrow();
    }
  });
});

describe("did:web · the W3C resolution URL, derived and never fetched", () => {
  test("no path → /.well-known/did.json", () => {
    expect(didWebUrl("did:web:duedale.com")).toBe("https://duedale.com/.well-known/did.json");
    expect(didWebUrl("did:web:indusland.xyz")).toBe("https://indusland.xyz/.well-known/did.json");
  });

  test("colon path → path segments, then /did.json", () => {
    expect(didWebUrl("did:web:example.com:u:alice")).toBe("https://example.com/u/alice/did.json");
    expect(parseDidWeb("did:web:example.com:u:alice")).toEqual({ host: "example.com", port: null, path: ["u", "alice"] });
  });

  test("a %3A port lands in the authority", () => {
    expect(didWebUrl("did:web:example.com%3A8443:org:acme")).toBe("https://example.com:8443/org/acme/did.json");
    expect(parseDidWeb("did:web:example.com%3A8443")).toEqual({ host: "example.com", port: 8443, path: [] });
  });
});

describe("did:web · one grammar everywhere", () => {
  test("the source anchors to exactly the whole string", () => {
    const re = new RegExp(`^${DID_WEB_SOURCE}$`);
    expect(re.test("did:web:duedale.com")).toBe(true);
    expect(re.test("did:web:duedale.com/place/x")).toBe(false); // a DID URL's path is outside the DID's own grammar
  });
});
