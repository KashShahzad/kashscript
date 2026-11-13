/**
 * M2 acceptance (ROADMAP done-when #2): the agent-identity round-trip. An owner
 * did:kash mints an MCP-conformant token (aud = resource URI, sub = owner,
 * act.sub = agent). The audience-check passes for the right aud and REJECTS a
 * wrong aud (RFC 8707 confused-deputy). Owner-binding verify extracts
 * {owner, agent} and the JWS verifies under the owner key — via JWKS (kid→x)
 * AND via did:kash self-certifying resolution.
 */

import { describe, it, expect } from "bun:test";
import { deriveDid, generateKeyPair } from "@kashscript/identity-core";

import { mintAgentToken, verifyAgentToken } from "../src/agent/token";
import { publishJwks } from "../src/jwks";
import { KashscriptIdentityMalformedDidError } from "../src/errors";

async function owner() {
  const kp = await generateKeyPair();
  return { did: deriveDid(kp.publicKey), publicKey: kp.publicKey, privateKey: kp.privateKey };
}

const AUD = "https://mcp.example.com/mcp";
const ISS = "https://as.kashscript.example";

describe("M2 agent-token — mint → audience-check → owner-binding round-trip", () => {
  it("mints an RFC 9068 at+jwt with the owner→agent binding", async () => {
    const o = await owner();
    const agentDid = deriveDid((await generateKeyPair()).publicKey);
    const { token, claims } = await mintAgentToken({
      owner: { did: o.did, privateKey: o.privateKey },
      agent: agentDid,
      audience: AUD,
      issuer: ISS,
      clientId: "agent-client-1",
      scope: "mcp:tools mcp:resources",
      expiresInSeconds: 300,
    });

    const [headerSeg] = token.split(".");
    const header = JSON.parse(Buffer.from(headerSeg!, "base64url").toString("utf8"));
    expect(header.typ).toBe("at+jwt");
    expect(header.alg).toBe("EdDSA");
    expect(header.kid).toBe(o.did);

    expect(claims.sub).toBe(o.did);
    expect(claims.act.sub).toBe(agentDid);
    expect(claims.aud).toBe(AUD);
    expect(claims.iss).toBe(ISS);
    expect(claims.client_id).toBe("agent-client-1");
  });

  it("verifies via did:kash self-certifying resolution (no JWKS, no network)", async () => {
    const o = await owner();
    const agentDid = deriveDid((await generateKeyPair()).publicKey);
    const { token } = await mintAgentToken({
      owner: { did: o.did, privateKey: o.privateKey },
      agent: agentDid,
      audience: AUD,
      issuer: ISS,
      clientId: "c",
      scope: "mcp:tools",
      expiresInSeconds: 300,
    });

    const res = await verifyAgentToken(token, { expectedAudience: AUD, expectedIssuer: ISS });
    expect(res.ok).toBe(true);
    expect(res.audienceOk).toBe(true);
    expect(res.ownerBinding).toEqual({ owner: o.did, agent: agentDid });
  });

  it("verifies via JWKS (kid → x)", async () => {
    const o = await owner();
    const agentDid = deriveDid((await generateKeyPair()).publicKey);
    const { token } = await mintAgentToken({
      owner: { did: o.did, privateKey: o.privateKey },
      agent: agentDid,
      audience: AUD,
      issuer: ISS,
      clientId: "c",
      scope: "mcp:tools",
      expiresInSeconds: 300,
    });

    const jwks = publishJwks([{ publicKey: o.publicKey, kid: o.did }]);
    const res = await verifyAgentToken(token, { expectedAudience: AUD, jwks });
    expect(res.ok).toBe(true);
    expect(res.ownerBinding?.owner).toBe(o.did);
    expect(res.ownerBinding?.agent).toBe(agentDid);
  });

  it("REJECTS a wrong audience (RFC 8707 confused-deputy defence)", async () => {
    const o = await owner();
    const agentDid = deriveDid((await generateKeyPair()).publicKey);
    const { token } = await mintAgentToken({
      owner: { did: o.did, privateKey: o.privateKey },
      agent: agentDid,
      audience: AUD,
      issuer: ISS,
      clientId: "c",
      scope: "mcp:tools",
      expiresInSeconds: 300,
    });

    const res = await verifyAgentToken(token, { expectedAudience: "https://evil.example.com/mcp" });
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("AUDIENCE_MISMATCH");
    expect(res.audienceOk).toBe(false);
    // The binding is still extractable (signature was valid) — useful for logs.
    expect(res.ownerBinding).toEqual({ owner: o.did, agent: agentDid });
  });

  it("treats :443 + trailing-slash audiences as equal (RFC 8707 canonicalization)", async () => {
    const o = await owner();
    const agentDid = deriveDid((await generateKeyPair()).publicKey);
    const { token } = await mintAgentToken({
      owner: { did: o.did, privateKey: o.privateKey },
      agent: agentDid,
      audience: "https://mcp.example.com:443/mcp",
      issuer: ISS,
      clientId: "c",
      scope: "mcp:tools",
      expiresInSeconds: 300,
    });
    const res = await verifyAgentToken(token, { expectedAudience: "https://mcp.example.com/mcp" });
    expect(res.ok).toBe(true);
  });

  it("rejects a tampered signature", async () => {
    const o = await owner();
    const agentDid = deriveDid((await generateKeyPair()).publicKey);
    const { token } = await mintAgentToken({
      owner: { did: o.did, privateKey: o.privateKey },
      agent: agentDid,
      audience: AUD,
      issuer: ISS,
      clientId: "c",
      scope: "mcp:tools",
      expiresInSeconds: 300,
    });
    const tampered = token.slice(0, -3) + (token.endsWith("AAA") ? "BBB" : "AAA");
    const res = await verifyAgentToken(tampered, { expectedAudience: AUD });
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("SIGNATURE_INVALID");
  });

  it("rejects an expired token and an issuer mismatch", async () => {
    const o = await owner();
    const agentDid = deriveDid((await generateKeyPair()).publicKey);
    const base = {
      owner: { did: o.did, privateKey: o.privateKey },
      agent: agentDid,
      audience: AUD,
      issuer: ISS,
      clientId: "c",
      scope: "mcp:tools",
    };

    const { token: expired } = await mintAgentToken({ ...base, expiresInSeconds: 60, nowSec: 1_000_000 });
    const resExp = await verifyAgentToken(expired, { expectedAudience: AUD, nowSec: 2_000_000 });
    expect(resExp.ok).toBe(false);
    expect(resExp.reason).toBe("EXPIRED");

    const { token: good } = await mintAgentToken({ ...base, expiresInSeconds: 300 });
    const resIss = await verifyAgentToken(good, { expectedAudience: AUD, expectedIssuer: "https://someone-else" });
    expect(resIss.ok).toBe(false);
    expect(resIss.reason).toBe("ISSUER_MISMATCH");
  });

  it("rejects minting with a malformed owner or agent DID", async () => {
    const o = await owner();
    await expect(
      mintAgentToken({
        owner: { did: "not-a-did", privateKey: o.privateKey },
        agent: deriveDid(o.publicKey),
        audience: AUD,
        issuer: ISS,
        clientId: "c",
        scope: "s",
        expiresInSeconds: 300,
      }),
    ).rejects.toBeInstanceOf(KashscriptIdentityMalformedDidError);
  });
});

describe("agent-token — red-team audit r1 hardening", () => {
  it("F1: refuses owner impersonation via a multi-tenant JWKS (key resolved by sub, not attacker kid)", async () => {
    const victim = await owner();
    const attacker = await owner();
    const agentDid = deriveDid((await generateKeyPair()).publicKey);

    // Attacker forges a token CLAIMING the victim as owner (`sub`), signs it with
    // the ATTACKER's key, and points `kid` at the attacker's own JWKS entry.
    const { token } = await mintAgentToken({
      owner: { did: victim.did, privateKey: attacker.privateKey },
      agent: agentDid,
      audience: AUD,
      issuer: ISS,
      clientId: "c",
      scope: "mcp:tools",
      expiresInSeconds: 300,
      kid: attacker.did,
    });

    // A JWKS that legitimately holds BOTH parties' keys under their own kids.
    const jwks = publishJwks([
      { publicKey: victim.publicKey, kid: victim.did },
      { publicKey: attacker.publicKey, kid: attacker.did },
    ]);

    const res = await verifyAgentToken(token, { expectedAudience: AUD, jwks });
    // Key is resolved by `sub` (victim) → the attacker's signature fails under it.
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("SIGNATURE_INVALID");
  });

  it("F1: a genuine token still verifies via JWKS keyed by the owner did (rotation-safe)", async () => {
    const o = await owner();
    const agentDid = deriveDid((await generateKeyPair()).publicKey);
    const { token } = await mintAgentToken({
      owner: { did: o.did, privateKey: o.privateKey },
      agent: agentDid,
      audience: AUD,
      issuer: ISS,
      clientId: "c",
      scope: "mcp:tools",
      expiresInSeconds: 300,
    });
    const jwks = publishJwks([{ publicKey: o.publicKey, kid: o.did }]);
    const res = await verifyAgentToken(token, { expectedAudience: AUD, jwks });
    expect(res.ok).toBe(true);
  });

  it("F2: rejects a non-did:kash sub as MALFORMED_CLAIMS (before any signature work)", async () => {
    const o = await owner();
    const agentDid = deriveDid((await generateKeyPair()).publicKey);
    const { token } = await mintAgentToken({
      owner: { did: o.did, privateKey: o.privateKey },
      agent: agentDid,
      audience: AUD,
      issuer: ISS,
      clientId: "c",
      scope: "mcp:tools",
      expiresInSeconds: 300,
    });
    const [h, p, s] = token.split(".") as [string, string, string];
    const claims = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
    claims.sub = "just-a-label"; // not a did:kash
    const badPayload = Buffer.from(JSON.stringify(claims)).toString("base64url");
    const res = await verifyAgentToken(`${h}.${badPayload}.${s}`, { expectedAudience: AUD });
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("MALFORMED_CLAIMS");
  });

  it("F5: clamps an over-large clock skew so a long-expired token is still rejected", async () => {
    const o = await owner();
    const agentDid = deriveDid((await generateKeyPair()).publicKey);
    const { token } = await mintAgentToken({
      owner: { did: o.did, privateKey: o.privateKey },
      agent: agentDid,
      audience: AUD,
      issuer: ISS,
      clientId: "c",
      scope: "mcp:tools",
      expiresInSeconds: 60,
      nowSec: 1_000_000,
    });
    // Token expired ~99_000s ago; a hostile 200_000s skew must NOT resurrect it.
    const res = await verifyAgentToken(token, { expectedAudience: AUD, nowSec: 1_100_000, clockSkewSeconds: 200_000 });
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("EXPIRED");
  });
});
