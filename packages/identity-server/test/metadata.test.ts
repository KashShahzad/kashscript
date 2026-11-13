/**
 * M2 — OAuth discovery metadata (RFC 8414 + RFC 9728) and RFC 8707 resource
 * canonicalization. These are the plain objects a venture serves at its
 * `.well-known` routes; the token `aud` must match the canonical resource.
 */

import { describe, it, expect } from "bun:test";
import {
  buildAuthorizationServerMetadata,
  buildProtectedResourceMetadata,
  OAUTH_AS_METADATA_PATH,
  OAUTH_PROTECTED_RESOURCE_METADATA_PATH,
} from "../src/metadata";
import { canonicalizeResourceUri, resourceUriEquals } from "../src/agent/resource";
import { KashscriptIdentityMalformedPayloadError } from "../src/errors";

describe("M2 metadata — RFC 8414 authorization-server metadata", () => {
  it("advertises S256-only PKCE and the RFC 9207 issuer response", () => {
    const md = buildAuthorizationServerMetadata({
      issuer: "https://as.example",
      authorizationEndpoint: "https://as.example/authorize",
      tokenEndpoint: "https://as.example/token",
      jwksUri: "https://as.example/jwks.json",
      scopesSupported: ["mcp:tools"],
    });
    expect(md.code_challenge_methods_supported).toEqual(["S256"]);
    expect(md.authorization_response_iss_parameter_supported).toBe(true);
    expect(md.response_types_supported).toEqual(["code"]);
    expect(md.scopes_supported).toEqual(["mcp:tools"]);
    expect(OAUTH_AS_METADATA_PATH).toBe("/.well-known/oauth-authorization-server");
  });
});

describe("M2 metadata — RFC 9728 protected-resource metadata", () => {
  it("canonicalizes the resource identifier", () => {
    const md = buildProtectedResourceMetadata({
      resource: "https://MCP.Example.com:443/mcp",
      authorizationServers: ["https://as.example"],
      scopesSupported: ["mcp:tools"],
    });
    expect(md.resource).toBe("https://mcp.example.com/mcp");
    expect(md.authorization_servers).toEqual(["https://as.example"]);
    expect(md.bearer_methods_supported).toEqual(["header"]);
    expect(OAUTH_PROTECTED_RESOURCE_METADATA_PATH).toBe("/.well-known/oauth-protected-resource");
  });
});

describe("M2 — RFC 8707 resource canonicalization", () => {
  it("lowercases host, drops the default port + bare trailing slash", () => {
    expect(canonicalizeResourceUri("HTTPS://MCP.Example.com:443/")).toBe("https://mcp.example.com");
    expect(canonicalizeResourceUri("https://mcp.example.com:8443/mcp")).toBe("https://mcp.example.com:8443/mcp");
    expect(resourceUriEquals("https://a.example:443/x", "https://a.example/x")).toBe(true);
  });

  it("rejects a fragment (RFC 8707 §2)", () => {
    expect(() => canonicalizeResourceUri("https://mcp.example.com/mcp#frag")).toThrow(
      KashscriptIdentityMalformedPayloadError,
    );
  });

  it("rejects a non-absolute URI", () => {
    expect(() => canonicalizeResourceUri("/relative/path")).toThrow(KashscriptIdentityMalformedPayloadError);
  });
});
