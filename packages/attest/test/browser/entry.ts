/**
 * The verifier, bundled for a browser (test/browser-smoke.test.ts). It reads the
 * vectors the page carries, runs attest's offline verifiers on them, and writes
 * what it found into `#out` as JSON. With `window.__NO_ED25519__` set it first
 * makes WebCrypto refuse Ed25519, as an older browser does — ES256 must still
 * verify there, and Ed25519 must come back "not checked", never "invalid".
 */

import { ed25519Available } from "@kashscript/identity-core";
import { verifyCountersignBundle } from "../../src/countersign";
import { verifyEnvelope } from "../../src/dsse";
import { makeKeyResolver, verifyHolderExport, verifyTrustList } from "../../src/holder";
import { verifySdJwt } from "../../src/sd-jwt/sd-jwt";
import { verifyKeyClaim } from "../../src/succession";
import { resolveDidKey } from "../../src/signing";
import { ed25519Verdicts } from "../ed25519/verdicts";

declare global {
  interface Window {
    __NO_ED25519__?: boolean;
  }
}

async function main(): Promise<Record<string, unknown>> {
  if (window.__NO_ED25519__) {
    const subtle = crypto.subtle;
    const original = subtle.importKey.bind(subtle);
    (subtle as { importKey: unknown }).importKey = (format: KeyFormat, key: unknown, alg: AlgorithmIdentifier, ...rest: unknown[]) => {
      const name = typeof alg === "string" ? alg : (alg as { name: string }).name;
      if (name === "Ed25519") return Promise.reject(new DOMException("Unrecognized algorithm name", "NotSupportedError"));
      return (original as (...a: unknown[]) => Promise<CryptoKey>)(format, key, alg, ...rest);
    };
  }
  const v = JSON.parse(document.getElementById("vectors")!.textContent!) as Record<string, any>;
  const ctx = v.context;
  const noKeys = makeKeyResolver(new Map(), new Map());
  const out: Record<string, unknown> = { userAgent: navigator.userAgent, ed25519Available: await ed25519Available() };

  out.es256TrustList = (await verifyTrustList(v.trustList, { pinnedPublishers: [ctx.trustPublisher], nowSec: ctx.nowSec })).ok;
  out.es256Presentation = (await verifySdJwt(v.presentation, { resolveKey: noKeys, requireKeyBinding: true, audience: ctx.audience, nonce: ctx.nonce, nowSec: ctx.nowSec })).reason ?? "ok";
  out.helperClaim = (await verifyKeyClaim(v.succession.claim)).reason ?? "ok";
  out.es256Export = (await verifyHolderExport(JSON.parse(v.es256Export), { pinnedPublishers: [ctx.trustPublisher], nowSec: ctx.nowSec })).reasons;
  out.countersignEs256 = (await verifyCountersignBundle(v.countersign)).reason ?? "ok";
  out.ed25519Export = (await verifyHolderExport(JSON.parse(v.pl1Export), { nowSec: 1_790_208_000 })).reasons;
  // confusion and malleability
  out.es256UnderEd25519Did = (await verifyEnvelope(v.negative.es256SignatureUnderEd25519Did.envelope, (k) => resolveDidKey(k))).ok;
  out.ed25519UnderP256Did = (await verifyTrustList(v.negative.ed25519SignatureUnderP256Did.envelope, { pinnedPublishers: [ctx.trustPublisher], nowSec: ctx.nowSec })).reason;
  out.dsseHighS = (await verifyTrustList(v.negative.dsseHighS.envelope, { pinnedPublishers: [ctx.trustPublisher], nowSec: ctx.nowSec })).reason;
  out.kbJwtHighS = (await verifySdJwt(v.negative.kbJwtHighS.presentation, { resolveKey: noKeys, requireKeyBinding: true, audience: ctx.audience, nonce: ctx.nonce, nowSec: ctx.nowSec })).reason;
  // AU-3 (A7-01): the forgery in another organisation's name — refused here as everywhere.
  out.kidNotIssuer = (await verifySdJwt(v.au3.kidNotIss, { resolveKey: noKeys, requireKeyBinding: true, audience: v.au3.context.audience, nonce: v.au3.context.nonce, nowSec: v.au3.context.nowSec })).reason;
  // AU-3 (A7-07): the Ed25519 acceptance rule gives this engine the pinned verdicts too (only where the engine has Ed25519 at all).
  if (out.ed25519Available === true) out.ed25519 = await ed25519Verdicts(v.ed25519);
  return out;
}

main()
  .then((o) => {
    document.getElementById("out")!.textContent = JSON.stringify(o);
  })
  .catch((e: unknown) => {
    document.getElementById("out")!.textContent = JSON.stringify({ crashed: String(e instanceof Error ? e.stack ?? e.message : e) });
  });
