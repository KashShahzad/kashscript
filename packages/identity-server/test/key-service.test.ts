/**
 * KS-Q4 — every signature the ceremony makes can come from a key service
 * (Indorania ADR-0003's first finding): the request, the countersignature, the
 * acceptance, the withdrawal and both halves of a key claim. The key never
 * leaves the service; what comes back is checked under the public key before
 * it is used; and for the same key, the bytes are the seed path's bytes.
 *
 * Also: the agent token's lifetime ceiling, a verifier's stated policy.
 */

import { describe, expect, it } from "bun:test";
import { createPrivateKey, sign as nodeSign } from "node:crypto";
import { deriveDid, generateKeyPair, kashEventSigningInput, type KashKeyPair } from "@kashscript/identity-core";
import { DST_COUNTERSIGN_REQUEST, signEnvelope, verifyCountersignBundle, type DsseEnvelope } from "@kashscript/attest";
import {
  acceptCountersignRequest,
  assembleCountersignBundle,
  claimCountersignKey,
  createCountersignRequest,
  withdrawCountersignRequest,
  type ExternalRelationshipSigningKey,
  type RelationshipSigningKey,
} from "../src/countersign";
import { RECOMMENDED_AGENT_TOKEN_LIFETIME_SECONDS, mintAgentToken, verifyAgentToken } from "../src/agent/token";

const T = 1_800_000_000;
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/** A key service: a seed behind a reference, signing bytes on request — Indorania's platform/signing shape. */
function service(seed: Uint8Array): (bytes: Uint8Array) => Promise<Uint8Array> {
  const key = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seed)]), format: "der", type: "pkcs8" });
  return async (bytes) => new Uint8Array(nodeSign(null, Buffer.from(bytes), key));
}

async function party(): Promise<KashKeyPair & { did: string }> {
  const kp = await generateKeyPair();
  return { ...kp, did: deriveDid(kp.publicKey) };
}

const seedKey = (p: KashKeyPair & { did: string }): RelationshipSigningKey => ({ did: p.did, publicKey: p.publicKey, privateKey: p.privateKey, custody: "subject-generated" });
const serviceKey = (p: KashKeyPair & { did: string }): ExternalRelationshipSigningKey => ({ did: p.did, publicKey: p.publicKey, custody: "subject-generated", sign: service(p.privateKey) });

async function subjectOf(holder: KashKeyPair & { did: string }): Promise<DsseEnvelope> {
  return signEnvelope({ order: "A-77", delivered: true }, "application/vnd.example.delivery+json", { keyid: holder.did, publicKey: holder.publicKey, sign: service(holder.privateKey), alg: "Ed25519" }, { canonical: true });
}

describe("the ceremony, signed through key services", () => {
  it("a bundle made wholly through key services verifies as two-signature proof under attest", async () => {
    const [holder, counterparty] = [await party(), await party()];
    const subject = await subjectOf(holder);
    let signedRequestBytes: Uint8Array | null = null;
    const holderService = service(holder.privateKey);
    const created = await createCountersignRequest({
      subject,
      requesterDid: holder.did,
      requesterSigner: { alg: "ed25519", publicKey: holder.publicKey, sign: async (b) => ((signedRequestBytes = b), holderService(b)) },
      statement: "Confirm you received the delivery for order A-77.",
      nowSec: T,
    });
    // The service was asked to sign exactly DST ‖ JCS({header, body}) — the recipe no platform needs to copy.
    expect(Buffer.from(signedRequestBytes!).toString("hex")).toBe(Buffer.from(kashEventSigningInput(created.request.header, created.request.body, DST_COUNTERSIGN_REQUEST)).toString("hex"));
    const accepted = await acceptCountersignRequest({ request: created.request, subject, signingKey: serviceKey(counterparty), nowSec: T + 60 });
    if (!accepted.ok) throw new Error(accepted.reason);
    const report = await verifyCountersignBundle(assembleCountersignBundle({ subject: accepted.envelope, request: created.request, acceptances: [accepted.acceptance] }));
    expect(report.reason).toBeNull();
    expect(report.twoSignatureProof).toBe(true);
  });

  it("for the same key, the countersignature, the acceptance, the withdrawal and the key claim are the seed path's bytes", async () => {
    const [holder, counterparty, successor] = [await party(), await party(), await party()];
    const subject = await subjectOf(holder);
    const created = await createCountersignRequest({ subject, requesterDid: holder.did, requesterPrivateKey: holder.privateKey, statement: "Confirm.", nowSec: T });
    const bySeed = await acceptCountersignRequest({ request: created.request, subject, signingKey: seedKey(counterparty), nowSec: T + 60 });
    const byService = await acceptCountersignRequest({ request: created.request, subject, signingKey: serviceKey(counterparty), nowSec: T + 60 });
    expect(byService).toEqual(bySeed);

    const wSeed = await withdrawCountersignRequest({ request: created.request, requesterPrivateKey: holder.privateKey, nowSec: T + 5 });
    const wService = await withdrawCountersignRequest({ request: created.request, requesterSigner: { alg: "ed25519", publicKey: holder.publicKey, sign: service(holder.privateKey) }, nowSec: T + 5 });
    expect(wService).toEqual(wSeed);

    const cSeed = await claimCountersignKey({ priorDid: counterparty.did, priorPrivateKey: counterparty.privateKey, successor: seedKey(successor), nowSec: T + 9 });
    const cService = await claimCountersignKey({
      priorDid: counterparty.did,
      priorSigner: { alg: "ed25519", publicKey: counterparty.publicKey, sign: service(counterparty.privateKey) },
      successor: serviceKey(successor),
      nowSec: T + 9,
    });
    expect(cService).toEqual(cSeed);
  });

  it("a key service answering with another key is refused before anything is made; one signer, never two, never none", async () => {
    const [holder, counterparty, other] = [await party(), await party(), await party()];
    const subject = await subjectOf(holder);
    const created = await createCountersignRequest({ subject, requesterDid: holder.did, requesterPrivateKey: holder.privateKey, statement: "Confirm.", nowSec: T });
    const lying: ExternalRelationshipSigningKey = { ...serviceKey(counterparty), sign: service(other.privateKey) };
    await expect(acceptCountersignRequest({ request: created.request, subject, signingKey: lying, nowSec: T + 60 })).rejects.toThrow();
    await expect(
      createCountersignRequest({ subject, requesterDid: holder.did, requesterSigner: { alg: "ed25519", publicKey: holder.publicKey, sign: service(other.privateKey) }, statement: "Confirm." }),
    ).rejects.toThrow("does not verify under its public key");
    await expect(
      createCountersignRequest({ subject, requesterDid: holder.did, requesterPrivateKey: holder.privateKey, requesterSigner: { alg: "ed25519", privateKey: holder.privateKey }, statement: "Confirm." }),
    ).rejects.toThrow();
    await expect(createCountersignRequest({ subject, requesterDid: holder.did, statement: "Confirm." })).rejects.toThrow();
    await expect(acceptCountersignRequest({ request: created.request, subject, signingKey: { did: counterparty.did, publicKey: counterparty.publicKey, custody: "subject-generated" } as never })).rejects.toThrow();
  });
});

describe("agent tokens — a verifier states how long a token it accepts may live", () => {
  async function owner() {
    const kp = await generateKeyPair();
    return { did: deriveDid(kp.publicKey), publicKey: kp.publicKey, privateKey: kp.privateKey };
  }
  const AUD = "https://mcp.example.com/mcp";

  it("recommends an hour; a minter that states it refuses longer; a verifier that states it refuses longer", async () => {
    expect(RECOMMENDED_AGENT_TOKEN_LIFETIME_SECONDS).toBe(3600);
    const o = await owner();
    const agent = deriveDid((await generateKeyPair()).publicKey);
    const base = { owner: { did: o.did, privateKey: o.privateKey }, agent, audience: AUD, issuer: o.did, clientId: agent, scope: "mcp:tools", nowSec: T };
    await expect(mintAgentToken({ ...base, expiresInSeconds: 3601, maxLifetimeSeconds: RECOMMENDED_AGENT_TOKEN_LIFETIME_SECONDS })).rejects.toThrow();
    const ok = await mintAgentToken({ ...base, expiresInSeconds: 3600, maxLifetimeSeconds: RECOMMENDED_AGENT_TOKEN_LIFETIME_SECONDS });
    expect((await verifyAgentToken(ok.token, { expectedAudience: AUD, nowSec: T + 10, maxLifetimeSeconds: 3600 })).ok).toBe(true);
    // A long token — Oreoasis's year-long booking mandate is one — still verifies where the verifier states no ceiling,
    // and is refused where it states one.
    const mandate = await mintAgentToken({ ...base, expiresInSeconds: 366 * 86_400 });
    expect((await verifyAgentToken(mandate.token, { expectedAudience: AUD, nowSec: T + 10 })).ok).toBe(true);
    const refused = await verifyAgentToken(mandate.token, { expectedAudience: AUD, nowSec: T + 10, maxLifetimeSeconds: 3600 });
    expect([refused.ok, refused.reason]).toEqual([false, "LIFETIME_TOO_LONG"]);
  });
});
