/**
 * RW-16: the wallet reads what an OpenID4VCI issuer and an OpenID4VP verifier
 * send — and still sends nothing it should not.
 */
import { describe, expect, test } from "bun:test";
import { isWalletError } from "../src/errors";
import { formOf } from "../src/headless/practice/network";
import type { HttpRequest } from "../src/platform";
import { decryptEcdhEs } from "../src/crypto/jwe-ecdh";
import { createHeadlessWallet, PRACTICE_T0, PracticeNetwork } from "../src/headless";
import { practiceWorld, receiveYes } from "./helpers";
import { makeTestVerifier } from "./x509-builder";

const ISS = "https://place.practice.invalid/issuer/";
const REDIRECT = "https://wallet.practice.invalid/back";

/** An issuer that offers by the authorization-code grant, records every request, and answers PAR with `parStatus`. */
function codeIssuer(net: PracticeNetwork, parStatus: number) {
  const seen: HttpRequest[] = [];
  const origin = new URL(ISS).origin;
  net.mount(origin, async (req) => {
    seen.push(req);
    const u = new URL(req.url);
    if (u.pathname === "/.well-known/openid-credential-issuer/issuer/") {
      return { status: 200, text: JSON.stringify({ credential_issuer: ISS, credential_endpoint: `${ISS}credential`, nonce_endpoint: `${ISS}nonce`, credential_configurations_supported: { "with-scope": { format: "dc+sd-jwt", scope: "a-scope" }, "no-scope": { format: "dc+sd-jwt" } } }) };
    }
    if (u.pathname === "/.well-known/oauth-authorization-server/issuer") {
      return { status: 200, text: JSON.stringify({ issuer: ISS, authorization_endpoint: `${ISS}authorize`, token_endpoint: `${ISS}token`, pushed_authorization_request_endpoint: `${ISS}par`, code_challenge_methods_supported: ["S256"] }) };
    }
    if (u.pathname === "/issuer/par") return parStatus === 201 ? { status: 201, text: JSON.stringify({ request_uri: "urn:x", expires_in: 60 }) } : { status: parStatus, text: JSON.stringify({ error: "invalid_client" }) };
    return { status: 404, text: "" };
  });
  return seen;
}

async function walletOn(net: PracticeNetwork, redirect: string | null = REDIRECT) {
  const person = await createHeadlessWallet({ practice: true, seed: `rw16-${Math.random()}`, now: () => PRACTICE_T0, transport: net.transport, ...(redirect !== null ? { authorizationRedirectUri: redirect } : {}) });
  return person;
}

const codeOffer = (issuerState?: string) => ({ credential_issuer: ISS, credential_configuration_ids: ["with-scope", "no-scope"], grants: { authorization_code: issuerState !== undefined ? { issuer_state: issuerState } : {} } });

describe("receive — the authorization-code grant, as far as it is built", () => {
  test("an offer with only an authorization-code grant is read, and redeeming it sends one pushed request with PKCE S256 — and no attestation", async () => {
    const net = new PracticeNetwork();
    const seen = codeIssuer(net, 400);
    const p = await walletOn(net);
    await p.wallet.proof.set(ISS, "on");
    const view = await p.wallet.receive.open(`openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(codeOffer("st-1")))}`);
    expect(view.grant).toBe("authorization_code");
    expect(view.needsTxCode).toBe(false);
    const snap = p.inspect.snapshot();
    const err = await p.wallet.receive.accept(view).catch((e) => e);
    expect(isWalletError(err, "ISSUER_REFUSED")).toBe(true);
    expect((err as { detail: string }).detail).toContain("invalid_client");
    const par = seen.find((r) => r.url.endsWith("/par"))!;
    const f = formOf(par);
    expect(f.get("response_type")).toBe("code");
    expect(f.get("code_challenge_method")).toBe("S256");
    expect(f.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(f.get("issuer_state")).toBe("st-1");
    expect(f.get("redirect_uri")).toBe(REDIRECT);
    expect(f.get("scope")).toBe("a-scope");
    expect(JSON.parse(f.get("authorization_details")!)).toEqual([{ type: "openid_credential", credential_configuration_id: "no-scope" }]);
    expect(Object.keys(par.headers).some((h) => h.toLowerCase().startsWith("oauth-client-attestation"))).toBe(false);
    expect(seen.some((r) => r.url.endsWith("/token") || r.url.endsWith("/credential") || r.url.endsWith("/nonce"))).toBe(false);
    // Nothing was kept, and no key was made.
    expect(p.inspect.snapshot()).toBe(snap);
  });

  test("the client_id is random and made for one request: two requests share none", async () => {
    const net = new PracticeNetwork();
    const seen = codeIssuer(net, 400);
    const p = await walletOn(net);
    await p.wallet.proof.set(ISS, "on");
    for (let i = 0; i < 2; i++) await p.wallet.receive.accept(await p.wallet.receive.open(codeOffer())).catch(() => undefined);
    const ids = seen.filter((r) => r.url.endsWith("/par")).map((r) => formOf(r).get("client_id"));
    expect(ids.length).toBe(2);
    expect(ids[0]).not.toBe(ids[1]);
    expect(formOf(seen.find((r) => r.url.endsWith("/par"))!).has("issuer_state")).toBe(false);
  });

  test("a place that takes the pushed request is told the next step is not built; nothing is stored", async () => {
    const net = new PracticeNetwork();
    codeIssuer(net, 201);
    const p = await walletOn(net);
    await p.wallet.proof.set(ISS, "on");
    const snap = p.inspect.snapshot();
    const err = await p.wallet.receive.accept(await p.wallet.receive.open(codeOffer())).catch((e) => e);
    expect(isWalletError(err, "NOT_BUILT")).toBe(true);
    expect(p.inspect.snapshot()).toBe(snap);
  });

  test("a wallet with no address to come back to sends nothing for this grant", async () => {
    const net = new PracticeNetwork();
    const seen = codeIssuer(net, 201);
    const p = await walletOn(net, null);
    await p.wallet.proof.set(ISS, "on");
    const err = await p.wallet.receive.accept(await p.wallet.receive.open(codeOffer())).catch((e) => e);
    expect(isWalletError(err, "NOT_BUILT")).toBe(true);
    expect(seen.some((r) => r.method === "POST")).toBe(false);
  });

  test("starting from a place the person picked: nothing is sent until records with it are on; then its metadata, and only its own", async () => {
    const net = new PracticeNetwork();
    const seen = codeIssuer(net, 400);
    const p = await walletOn(net);
    const before = await p.wallet.receive.start(ISS);
    expect(before.offer).toBeNull();
    expect(seen.length).toBe(0);
    await p.wallet.proof.set(ISS, "on");
    const view = await p.wallet.receive.start(ISS);
    expect(view.offer?.credential_configuration_ids).toEqual(["with-scope", "no-scope"]);
    await p.wallet.receive.accept(view, { configurationIds: ["no-scope"] }).catch(() => undefined);
    const f = formOf(seen.find((r) => r.url.endsWith("/par"))!);
    expect(f.has("scope")).toBe(false);
    expect(JSON.parse(f.get("authorization_details")!)).toEqual([{ type: "openid_credential", credential_configuration_id: "no-scope" }]);
  });

  test("an authorization server document that names another issuer is not used: no pushed request is sent", async () => {
    const net = new PracticeNetwork();
    const seen: HttpRequest[] = [];
    const origin = new URL(ISS).origin;
    net.mount(origin, async (req) => {
      seen.push(req);
      const u = new URL(req.url);
      if (u.pathname === "/.well-known/openid-credential-issuer/issuer/") return { status: 200, text: JSON.stringify({ credential_issuer: ISS, credential_endpoint: `${ISS}credential`, credential_configurations_supported: { a: { format: "dc+sd-jwt", scope: "a" } } }) };
      if (u.pathname === "/.well-known/oauth-authorization-server/issuer") return { status: 200, text: JSON.stringify({ issuer: `${origin}/someone-else`, authorization_endpoint: `${ISS}authorize`, pushed_authorization_request_endpoint: `${ISS}par` }) };
      return { status: 404, text: "" };
    });
    const p = await walletOn(net);
    await p.wallet.proof.set(ISS, "on");
    const err = await p.wallet.receive.accept(await p.wallet.receive.open({ ...codeOffer(), credential_configuration_ids: ["a"] })).catch((e) => e);
    expect(isWalletError(err, "OFFER_ORIGIN")).toBe(true);
    expect(seen.some((r) => r.method === "POST")).toBe(false);
  });

  test("the pre-authorized flow is unchanged: anonymous, no client id", async () => {
    const w = await practiceWorld();
    await receiveYes(w);
    expect(w.person.inspect.traffic().some((r) => r.body !== null && r.body.includes("client_id"))).toBe(false);
  });
});

/* ── requests ─────────────────────────────────────────────────────────────────────────────────── */

const VHOST = "verifier.x509.practice.invalid";
const VORIGIN = `https://${VHOST}`;

async function x509World(opts: { dns?: string[] } = {}) {
  const net = new PracticeNetwork();
  const v = await makeTestVerifier(opts.dns ?? [VHOST]);
  const enc = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])) as CryptoKeyPair;
  const encJwk = { ...((await crypto.subtle.exportKey("jwk", enc.publicKey)) as JsonWebKey), kid: "enc-1", use: "enc", alg: "ECDH-ES" };
  const objects = new Map<string, string>();
  const posts: HttpRequest[] = [];
  const fetches: HttpRequest[] = [];
  net.mount(VORIGIN, async (req) => {
    const u = new URL(req.url);
    if (u.pathname.startsWith("/request/")) {
      fetches.push(req);
      const o = objects.get(u.pathname);
      return o === undefined ? { status: 404, text: "" } : { status: 200, text: o };
    }
    if (u.pathname === "/response") {
      posts.push(req);
      return { status: 200, text: "{}" };
    }
    return { status: 404, text: "" };
  });
  const person = await createHeadlessWallet({ practice: true, seed: "rw16-vp", now: () => Math.floor(Date.UTC(2026, 10, 23) / 1000), transport: net.transport });
  const base = (clientId: string, over: Record<string, unknown> = {}) => ({
    client_id: clientId,
    response_type: "vp_token",
    response_mode: "direct_post.jwt",
    response_uri: `${VORIGIN}/response`,
    nonce: "n-1",
    state: "s-1",
    dcql_query: { credentials: [{ id: "c", format: "dc+sd-jwt", meta: { vct_values: ["urn:eudi:pid:1"] } }] },
    client_metadata: { jwks: { keys: [encJwk] }, encrypted_response_enc_values_supported: ["A128GCM"] },
    ...over,
  });
  /** Publish a signed request object by reference; returns the link the wallet is handed. */
  const publish = async (clientId: string, payload: Record<string, unknown>, header: Record<string, unknown> = {}, method?: "post") => {
    const path = `/request/${objects.size}`;
    objects.set(path, await v.sign(header, payload));
    return `openid4vp://authorize?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent(VORIGIN + path)}${method ? "&request_uri_method=post" : ""}`;
  };
  return { net, v, enc, person, base, publish, posts, fetches, hashId: `x509_hash:${v.hash}` };
}

describe("present — requests by reference, signed, and what the wallet sends back", () => {
  test("a signed x509_hash request with no ask is read, refused, and nothing is sent — not even an error", async () => {
    const x = await x509World();
    const link = await x.publish(x.hashId, x.base(x.hashId));
    const snap = x.person.inspect.snapshot();
    const r = await x.person.wallet.present.read(link);
    expect(r.kind).toBe("no-ask");
    expect(x.fetches.length).toBe(1);
    expect(x.fetches[0]!.method).toBe("GET");
    expect(x.posts.length).toBe(0);
    expect(x.person.inspect.snapshot()).toBe(snap);
    expect(isWalletError(await x.person.wallet.present.open(link).catch((e) => e), "ASK_REFUSED")).toBe(true);
  });

  test("request_uri_method=post fetches by POST", async () => {
    const x = await x509World();
    const link = await x.publish(x.hashId, x.base(x.hashId), {}, "post");
    expect((await x.person.wallet.present.read(link)).kind).toBe("no-ask");
    expect(x.fetches[0]!.method).toBe("POST");
    expect(x.fetches[0]!.headers.accept).toBe("application/oauth-authz-req+jwt");
  });

  test("an untrusted request — wrong hash, bad signature, mismatched client_id, unknown prefix — sends nothing at all", async () => {
    const x = await x509World();
    const wrongHash = `x509_hash:${"A".repeat(43)}`;
    // A request object whose signature is broken, served from its own host.
    const good = await x.v.sign({}, x.base(x.hashId));
    const broken = `${good.slice(0, -4)}${good.endsWith("AAAA") ? "BBBB" : "AAAA"}`;
    x.net.mount("https://broken.practice.invalid", async () => ({ status: 200, text: broken }));
    const cases = [
      await x.publish(wrongHash, x.base(wrongHash)),
      `openid4vp://authorize?client_id=${encodeURIComponent(x.hashId)}&request_uri=${encodeURIComponent("https://broken.practice.invalid/r")}`,
      // The outer client_id differs from the one inside.
      (await x.publish(x.hashId, x.base(x.hashId))).replace(encodeURIComponent(x.hashId), encodeURIComponent(`${x.hashId}x`)),
      await x.publish("unknown_prefix:abc", x.base("unknown_prefix:abc")),
    ];
    for (const link of cases) {
      const r = await x.person.wallet.present.read(link);
      expect(r.kind).toBe("untrusted");
    }
    expect(x.posts.length).toBe(0);
  });

  test("x509_san_dns: the name must be in the certificate and the response_uri on that host", async () => {
    const x = await x509World();
    const id = `x509_san_dns:${VHOST}`;
    expect((await x.person.wallet.present.read(await x.publish(id, x.base(id)))).kind).toBe("no-ask");
    const other = "x509_san_dns:not-in-cert.practice.invalid";
    expect((await x.person.wallet.present.read(await x.publish(other, x.base(other)))).kind).toBe("untrusted");
    const y = await x509World({ dns: ["elsewhere.practice.invalid"] });
    const id2 = "x509_san_dns:elsewhere.practice.invalid";
    expect((await y.person.wallet.present.read(await y.publish(id2, y.base(id2)))).kind).toBe("untrusted");
  });

  test("a verified request that is itself broken is not answered on its own; the person may tell the verifier, encrypted to its key", async () => {
    const x = await x509World();
    const link = await x.publish(x.hashId, x.base(x.hashId, { nonce: undefined }));
    const r = await x.person.wallet.present.read(link);
    expect(r.kind).toBe("invalid");
    expect(x.posts.length).toBe(0);
    if (r.kind !== "invalid") throw new Error("unreachable");
    expect(r.error).toBe("invalid_request");
    const snap = x.person.inspect.snapshot();
    await x.person.wallet.present.report(r);
    expect(x.posts.length).toBe(1);
    const jwe = formOf(x.posts[0]!).get("response")!;
    const body = JSON.parse(new TextDecoder().decode(await decryptEcdhEs(jwe, x.enc.privateKey)));
    expect(body).toMatchObject({ error: "invalid_request", state: "s-1" });
    expect(Object.keys(body).sort()).toEqual(["error", "error_description", "state"]);
    expect(x.person.inspect.snapshot()).toBe(snap);
  });

  test("transaction data of a type the wallet does not know is invalid_transaction_data", async () => {
    const x = await x509World();
    const r = await x.person.wallet.present.read(await x.publish(x.hashId, x.base(x.hashId, { transaction_data: ["eyJ0eXBlIjoieCJ9"] })));
    expect(r.kind === "invalid" && r.error).toBe("invalid_transaction_data");
  });

  test("redirect_uri: unsigned only, and only to its own response_uri", async () => {
    const x = await x509World();
    const id = `redirect_uri:${VORIGIN}/response`;
    const q = (o: Record<string, unknown>) => `openid4vp://authorize?${new URLSearchParams(Object.entries(o).filter(([, v]) => v !== undefined).map(([k, v]) => [k, typeof v === "string" ? v : JSON.stringify(v)])).toString()}`;
    expect((await x.person.wallet.present.read(q(x.base(id, { response_mode: "direct_post", client_metadata: undefined })))).kind).toBe("no-ask");
    expect((await x.person.wallet.present.read(q(x.base(`redirect_uri:${VORIGIN}/elsewhere`, { response_mode: "direct_post" })))).kind).toBe("untrusted");
    expect((await x.person.wallet.present.read(await x.publish(id, x.base(id))))).toMatchObject({ kind: "untrusted" });
    expect(x.posts.length).toBe(0);
  });

  test("the v1 by-value ask request still works end to end", async () => {
    const w = await practiceWorld();
    await receiveYes(w);
    const view = await w.wallet.present.open(await w.verifier.request(w.verifier.ask("ask:rw16-v1")));
    expect(view.reply.mode).toBe("direct_post");
    await w.wallet.present.yes(view);
    expect(w.verifier.received.length).toBe(1);
  });
});
