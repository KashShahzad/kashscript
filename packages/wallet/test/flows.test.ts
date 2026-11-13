import { describe, expect, test } from "bun:test";
import { generateKeyPair, deriveDid, parseDid } from "@kashscript/identity-core";
import { decodeJws, issueSdJwt, jwkOf, linkabilityBetween } from "@kashscript/attest/sd-jwt";
import { askSha256, FORBIDDEN_VOUCHER_FIELDS, THANK_YOU_VCT, verifyRedemption, verifySessionReceipt } from "@kashscript/attest/exchange";
import { makeKeyResolver, verifyStatusList } from "@kashscript/attest/holder";
import { isWalletError } from "../src/errors";
import type { HttpRequest } from "../src/platform";
import { practiceWorld, receiveYes } from "./helpers";

const DAY = 86_400;

describe("receive — the handoff", () => {
  test("keys are made only after the place hands over a token, so a refused offer changes nothing", async () => {
    const w = await practiceWorld();
    await w.wallet.proof.set(w.issuer.origin, "on");
    const offer = w.issuer.offer(["practice-visit"]);
    await w.wallet.receive.accept(await w.wallet.receive.open(offer));
    const snap = w.person.inspect.snapshot();
    const replay = await w.wallet.receive.accept(await w.wallet.receive.open(offer)).catch((e) => e);
    expect(isWalletError(replay, "ISSUER_REFUSED")).toBe(true);
    expect(w.person.inspect.snapshot()).toBe(snap);
  });

  test("each key proof carries a key made for this place — never one shown elsewhere", async () => {
    const w = await practiceWorld();
    await receiveYes(w);
    await w.wallet.proof.set(w.cafe.origin, "on");
    await w.wallet.receive.accept(await w.wallet.receive.open(w.cafe.issuer.offer(["practice-thank-you"])));
    expect(w.issuer.seenKeys.length).toBe(6);
    expect(w.cafe.issuer.seenKeys.some((k) => w.issuer.seenKeys.includes(k))).toBe(false);
  });

  test("an offer link on another host is refused unopened; an endpoint elsewhere is refused before any key is sent", async () => {
    const w = await practiceWorld();
    const other = "https://elsewhere.practice.invalid";
    w.net.mount(other, async () => ({ status: 200, text: JSON.stringify({ credential_issuer: w.issuer.origin, credential_configuration_ids: ["practice-visit"], grants: { "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "x" } } }) }));
    await w.wallet.proof.set(other, "on");
    const byRef = await w.wallet.receive.open(`openid-credential-offer://?credential_offer_uri=${encodeURIComponent(`${other}/offer`)}`).catch((e) => e);
    expect(isWalletError(byRef, "OFFER_ORIGIN")).toBe(true);

    const rogue = "https://rogue.practice.invalid";
    w.net.mount(rogue, async (req: HttpRequest) => {
      if (req.url.endsWith("openid-credential-issuer")) return { status: 200, text: JSON.stringify({ credential_issuer: rogue, credential_endpoint: `${other}/credential`, nonce_endpoint: `${rogue}/nonce`, credential_configurations_supported: {} }) };
      return { status: 404, text: "" };
    });
    await w.wallet.proof.set(rogue, "on");
    const offer = { credential_issuer: rogue, credential_configuration_ids: ["x"], grants: { "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "y" } } };
    const res = await w.wallet.receive.accept(await w.wallet.receive.open(offer)).catch((e) => e);
    expect(isWalletError(res, "OFFER_ORIGIN")).toBe(true);
    expect(w.person.inspect.traffic().some((r) => r.url.startsWith(other) && r.method === "POST")).toBe(false);
  });

  test("an issuer that would need a client id is refused — no wallet identifier is ever sent", async () => {
    const w = await practiceWorld();
    const origin = "https://named.practice.invalid";
    w.net.mount(origin, async (req: HttpRequest) => {
      if (req.url.endsWith("openid-credential-issuer")) return { status: 200, text: JSON.stringify({ credential_issuer: origin, credential_endpoint: `${origin}/c`, nonce_endpoint: `${origin}/n`, credential_configurations_supported: {} }) };
      if (req.url.endsWith("oauth-authorization-server")) return { status: 200, text: JSON.stringify({ issuer: origin, token_endpoint: `${origin}/t` }) };
      return { status: 404, text: "" };
    });
    await w.wallet.proof.set(origin, "on");
    const offer = { credential_issuer: origin, credential_configuration_ids: ["x"], grants: { "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "z" } } };
    expect(isWalletError(await w.wallet.receive.accept(await w.wallet.receive.open(offer)).catch((e) => e), "ISSUER_REFUSED")).toBe(true);
  });

  test("an issuer whose identifier has a path is looked up where RFC 8414 and OpenID4VCI 1.0 put it — between the host and the path", async () => {
    const w = await practiceWorld();
    const origin = "https://tenant.practice.invalid";
    const issuer = `${origin}/tenant/a`;
    const ok = (body: unknown) => ({ status: 200, text: JSON.stringify(body) });
    w.net.mount(origin, async (req: HttpRequest) => {
      const path = new URL(req.url).pathname;
      if (path === "/.well-known/openid-credential-issuer/tenant/a") return ok({ credential_issuer: issuer, credential_endpoint: `${issuer}/credential`, nonce_endpoint: `${issuer}/nonce`, authorization_servers: [issuer], credential_configurations_supported: {} });
      if (path === "/.well-known/oauth-authorization-server/tenant/a") return ok({ issuer, token_endpoint: `${issuer}/token`, "pre-authorized_grant_anonymous_access_supported": true });
      if (path === "/tenant/a/token") return { status: 400, text: JSON.stringify({ error: "invalid_grant" }) };
      return { status: 404, text: "" };
    });
    await w.wallet.proof.set(origin, "on");
    const offer = { credential_issuer: issuer, credential_configuration_ids: ["x"], grants: { "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "p" } } };
    expect(isWalletError(await w.wallet.receive.accept(await w.wallet.receive.open(offer)).catch((e) => e), "ISSUER_REFUSED")).toBe(true);
    const asked = w.person.inspect.traffic().map((r) => new URL(r.url).pathname);
    expect(asked).toContain("/.well-known/openid-credential-issuer/tenant/a");
    expect(asked).toContain("/.well-known/oauth-authorization-server/tenant/a");
    expect(asked).toContain("/tenant/a/token"); // it got as far as the token endpoint, so both documents were found
    expect(asked.some((p) => p.startsWith("/tenant/a/.well-known"))).toBe(false); // never the OpenID Connect form
  });

  test("a thank-you carrying anything that could be summed is not kept", async () => {
    const w = await practiceWorld();
    const giver = await generateKeyPair();
    const did = deriveDid(giver.publicKey);
    const origin = "https://greedy.practice.invalid";
    const ok = (body: unknown) => ({ status: 200, text: JSON.stringify(body) });
    w.net.mount(origin, async (req: HttpRequest) => {
      const path = new URL(req.url).pathname;
      if (path === "/.well-known/openid-credential-issuer") {
        return ok({ credential_issuer: origin, credential_endpoint: `${origin}/credential`, nonce_endpoint: `${origin}/nonce`, credential_configurations_supported: { ty: { format: "dc+sd-jwt", vct: THANK_YOU_VCT } } });
      }
      if (path === "/.well-known/oauth-authorization-server") return ok({ issuer: origin, token_endpoint: `${origin}/token`, "pre-authorized_grant_anonymous_access_supported": true });
      if (path === "/token") return ok({ access_token: "t", token_type: "Bearer" });
      if (path === "/nonce") return ok({ c_nonce: "n" });
      const proof = decodeJws(JSON.parse(req.body!).proofs.jwt[0])!;
      const cnf = { jwk: jwkOf(parseDid(proof.header.kid as string)) };
      const greedy = await issueSdJwt({ header: { kid: did }, claims: { iss: did, iat: 0, exp: w.now() + DAY, vct: THANK_YOU_VCT, cnf, for: { act: "confirmed-session", session: "s" }, value: "Practice: ten points", redeemAt: "here", points: 10 }, signer: giver });
      return ok({ credentials: [{ credential: greedy }] });
    });
    await w.wallet.proof.set(origin, "on");
    const offer = { credential_issuer: origin, credential_configuration_ids: ["ty"], grants: { "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "c" } } };
    const res = await w.wallet.receive.accept(await w.wallet.receive.open(offer)).catch((e) => e);
    expect(isWalletError(res, "RECORD_REFUSED")).toBe(true);
    expect((res as { detail: string }).detail).toContain("BALANCE_FIELD");
    expect((await w.wallet.records.list()).length).toBe(0);
  });
});

describe("present — one yes, never the data", () => {
  test("a changed ask, a query asking for more, a stranger's request or a lapsed ask is refused before anything is shown", async () => {
    const w = await practiceWorld();
    await receiveYes(w);
    const ask = w.verifier.ask("ask:practice-refusals");
    const good = await w.verifier.request(ask);
    const refused = async (req: Record<string, unknown>) => isWalletError(await w.wallet.present.open(req).catch((e) => e), "ASK_REFUSED");
    expect(await refused({ ...good, kash_ask: { ...ask, why: "Something else entirely was meant here." } })).toBe(true);
    expect(await refused({ ...good, dcql_query: { credentials: [] } })).toBe(true);
    expect(await refused({ ...good, client_id: w.other.did })).toBe(true);
    const lapsed = { ...ask, expiresAtUnix: w.now() - 1 };
    expect(await refused({ ...good, kash_ask: lapsed, kash_ask_sha256: await askSha256(lapsed) })).toBe(true);
    const improv = { ...ask, needs: [{ id: "n1", predicate: "improved-the-way-this-work-is-done", withinDays: 30 }] };
    expect(await refused({ ...good, kash_ask: improv, kash_ask_sha256: await askSha256(improv) })).toBe(true);
  });

  test("an ask that differs from the public list's copy is refused; one not in the list is shown with a warning", async () => {
    const w = await practiceWorld();
    await receiveYes(w);
    const ask = w.verifier.ask("ask:practice-library");
    await w.wallet.asks.remember({ ...ask, why: "The published version said something different from this." });
    expect(isWalletError(await w.wallet.present.open(await w.verifier.request(ask)).catch((e) => e), "ASK_REFUSED")).toBe(true);
    const unknown = await w.wallet.present.open(await w.verifier.request(w.verifier.ask("ask:practice-unlisted")));
    expect(unknown.library).toBe("not-in-library");
    expect(unknown.libraryText).toContain("isn't in your copy");
  });

  test("no sends nothing, stores nothing, logs nothing — and the verifier hears nothing", async () => {
    const w = await practiceWorld();
    await receiveYes(w);
    const view = await w.wallet.present.open(await w.verifier.request(w.verifier.ask("ask:practice-no")));
    const [snap, sent] = [w.person.inspect.snapshot(), w.person.inspect.traffic().length];
    expect(w.wallet.present.no(view)).toBeUndefined();
    expect(w.person.inspect.snapshot()).toBe(snap);
    expect(w.person.inspect.traffic().length).toBe(sent);
    expect(w.verifier.received.length).toBe(0);
    expect(await w.wallet.log.list()).toEqual([]);
  });

  test("a revoked copy is never offered; two verifiers' presentations share nothing", async () => {
    const w = await practiceWorld();
    await receiveYes(w);
    const copies = (await w.wallet.records.list()).filter((e) => e.artifact.kind === "sd-jwt");
    for (const c of copies.slice(0, 4)) w.issuer.revoke(c.manifest.status!);
    await w.wallet.status.carry(await w.issuer.statusList());
    const list = await verifyStatusList(await w.issuer.statusList(), { resolveKey: makeKeyResolver(new Map(), new Map()), nowSec: w.now(), source: "fetched" });
    w.verifier.statusLists = [list];
    const view = await w.wallet.present.open(await w.verifier.request(w.verifier.ask("ask:practice-revoked")));
    expect(view.chosen.n1).toBe(copies[4]!.slot);
    await w.wallet.present.yes(view);
    expect(w.verifier.received[0]!.report.status.state).toBe("not-revoked");
    const other = await w.wallet.present.open(await w.other.request(w.other.ask("ask:practice-none-left")));
    expect(other.answerable).toBe(false);
    expect(other.needs[0]!.missing).not.toBeNull();
  });

  test("the holder may note an ask asked too much — in their own log, never sent", async () => {
    const w = await practiceWorld();
    await receiveYes(w);
    const view = await w.wallet.present.open(await w.verifier.request(w.verifier.ask("ask:practice-too-much")));
    const sent = w.person.inspect.traffic().length;
    await w.wallet.present.noteExcessive(view, ["R1-predicates-only"], "It wanted more than a yes.");
    expect((await w.wallet.log.list())[0]).toMatchObject({ kind: "excessive-ask", rules: ["R1-predicates-only"] });
    expect(w.person.inspect.traffic().length).toBe(sent);
  });

  test("linkability between two verifiers' yeses is empty", async () => {
    const w = await practiceWorld();
    await receiveYes(w);
    await w.wallet.present.yes(await w.wallet.present.open(await w.verifier.request(w.verifier.ask("ask:practice-l1"))));
    await w.wallet.present.yes(await w.wallet.present.open(await w.other.request(w.other.ask("ask:practice-l2"))));
    expect(await linkabilityBetween(w.verifier.received[0]!.presentation, w.other.received[0]!.presentation)).toEqual([]);
  });
});

describe("thank-yous", () => {
  test("single notes in words, nothing summable; used only with whoever gave it, and only once", async () => {
    const w = await practiceWorld();
    await w.wallet.proof.set(w.cafe.origin, "on", w.cafe.name);
    await w.wallet.receive.accept(await w.wallet.receive.open(w.cafe.issuer.offer(["practice-thank-you"])));
    const [note] = await w.wallet.thankYous.list();
    expect(note).toBeDefined();
    expect(Object.keys(note!).filter((k) => FORBIDDEN_VOUCHER_FIELDS.includes(k.toLowerCase()))).toEqual([]);
    expect(note!.words).toContain("A practice café");

    const elsewhere = await w.wallet.thankYous.redeem(note!.id, { client_id: w.verifier.did, nonce: "n" }).catch((e) => e);
    expect(isWalletError(elsewhere, "REDEEM_ELSEWHERE")).toBe(true);

    const presentation = await w.wallet.thankYous.redeem(note!.id, { client_id: w.cafe.issuer.did, nonce: "counter-nonce" });
    const resolveKey = makeKeyResolver(new Map(), new Map());
    const before = [await verifyStatusList(await w.cafe.issuer.statusList(), { resolveKey, nowSec: w.now() })];
    expect((await verifyRedemption(presentation, { resolveKey, nonce: "counter-nonce", statusLists: before, nowSec: w.now() })).ok).toBe(true);
    const held = (await w.wallet.records.get(note!.id))!;
    w.cafe.issuer.revoke(held.manifest.status!);
    const after = [await verifyStatusList(await w.cafe.issuer.statusList(), { resolveKey, nowSec: w.now() })];
    expect((await verifyRedemption(presentation, { resolveKey, nonce: "counter-nonce", statusLists: after, nowSec: w.now() })).reason).toBe("USED_OR_WITHDRAWN");
  });
});

describe("sessions — the person's signature on each line", () => {
  test("unset asks first; off signs and sends nothing; the line stays pending", async () => {
    const w = await practiceWorld();
    const line = await (async () => {
      await w.wallet.proof.set(w.cafe.origin, "on");
      const j = await w.wallet.sessions.join(w.cafe.origin);
      if (j.status !== "joined") throw new Error("join");
      return { did: j.personDid, open: await w.cafe.open(j.personDid) };
    })();
    await w.wallet.proof.set(w.cafe.origin, "off");
    const snap = w.person.inspect.snapshot();
    expect((await w.wallet.sessions.cosign(w.cafe.origin, line.open)).status).toBe("off");
    expect(w.person.inspect.snapshot()).toBe(snap);
    expect((await w.wallet.sessions.join("https://new.practice.invalid")).status).toBe("needs-choice");
    expect((await verifySessionReceipt(w.cafe.receipt(line.did), { nowSec: w.now() })).proof).toBe(false);
  });

  test("a line not written by the place, or naming someone else, is refused unsigned", async () => {
    const w = await practiceWorld();
    await w.wallet.proof.set(w.cafe.origin, "on");
    const j = await w.wallet.sessions.join(w.cafe.origin);
    if (j.status !== "joined") throw new Error("join");
    const stranger = deriveDid((await generateKeyPair()).publicKey);
    const wrongPerson = await w.cafe.open(stranger);
    expect(isWalletError(await w.wallet.sessions.cosign(w.cafe.origin, wrongPerson).catch((e) => e), "LINE_REFUSED")).toBe(true);
    const open = await w.cafe.open(j.personDid);
    const forged = { ...open, signatures: [{ keyid: stranger, sig: open.signatures[0]!.sig }] };
    expect(isWalletError(await w.wallet.sessions.cosign(w.cafe.origin, forged).catch((e) => e), "LINE_REFUSED")).toBe(true);
  });

  test("a complete session is kept as signed by both; the total is shared and the item stays hashed", async () => {
    const w = await practiceWorld();
    await w.wallet.proof.set(w.cafe.origin, "on");
    const j = await w.wallet.sessions.join(w.cafe.origin);
    if (j.status !== "joined") throw new Error("join");
    for (const line of [await w.cafe.open(j.personDid), await w.cafe.flow(j.personDid, { label: "a pot of tea", amount: "300.00" }), await w.cafe.close(j.personDid, { amount: "300.00", currency: "PKR" }, 1)]) {
      const r = await w.wallet.sessions.cosign(w.cafe.origin, line);
      if (r.status !== "signed") throw new Error("cosign");
      w.cafe.accept(j.personDid, r.line);
    }
    const slot = await w.wallet.sessions.keep(w.cafe.origin, w.cafe.receipt(j.personDid));
    const kept = (await w.wallet.records.get(slot))!;
    expect(kept.manifest.type.attestation).toBe("countersigned");
    expect(JSON.stringify(kept.artifact.value)).not.toContain("a pot of tea");
  });
});
