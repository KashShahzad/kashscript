/**
 * RW-19 B — two spellings, one key, everywhere the holder compares (d97(h); A7-02's rule).
 *
 * A self-certifying key is called `did:key` where a stranger reads; `did:kash`
 * is the same key's house spelling, read for ever. So a trust list signed
 * under one spelling matches a pin given under the other, two reports of one
 * publisher are one publisher, a self-listed issuer matches its signer across
 * spellings, and the holder's resolution order treats a `did:key` as
 * self-certifying at step 1.
 */

import { describe, expect, it } from "bun:test";
import { deriveDid, generateKeyPair, toDidKey } from "@kashscript/identity-core";
import { makeKeyResolver } from "../src/holder/keys";
import {
  TRUST_LIST_FORMAT,
  currentTrustLists,
  findListing,
  signTrustList,
  verifyTrustList,
  type TrustListPayload,
} from "../src/holder/trust-list";

const WINDOW = { issuedAtUnix: 1_767_225_600, validFromUnix: 1_767_225_600, validUntilUnix: 2_082_758_400 };
const NOW = 1_800_000_000;

async function publisher() {
  const kp = await generateKeyPair();
  const kash = deriveDid(kp.publicKey);
  return { kp, kash, key: toDidKey(kash) };
}

function listOf(publisherDid: string, issuers: TrustListPayload["issuers"], version = 1): TrustListPayload {
  return { format: TRUST_LIST_FORMAT, listId: "spellings", version, publisher: publisherDid, ...WINDOW, issuers };
}

describe("RW-19 B — the trust list across spellings", () => {
  it("a list published and signed under its did:key spelling verifies, and a did:kash pin still pins it", async () => {
    const { kp, kash, key } = await publisher();
    const env = await signTrustList(listOf(key, []), { keyid: key, privateKey: kp.privateKey, publicKey: kp.publicKey });
    const r = await verifyTrustList(env, { pinnedPublishers: [kash], nowSec: NOW });
    expect(r.ok).toBe(true);
    expect(r.publisher).toBe(key);
    expect(r.pinned).toBe(true);
  });

  it("and the mirror: published under did:kash, pinned under did:key", async () => {
    const { kp, kash, key } = await publisher();
    const env = await signTrustList(listOf(kash, []), { keyid: kash, privateKey: kp.privateKey, publicKey: kp.publicKey });
    const r = await verifyTrustList(env, { pinnedPublishers: [key], nowSec: NOW });
    expect(r.ok).toBe(true);
    expect(r.pinned).toBe(true);
  });

  it("a different key's pin still pins nothing", async () => {
    const { kp, kash } = await publisher();
    const other = await publisher();
    const env = await signTrustList(listOf(kash, []), { keyid: kash, privateKey: kp.privateKey, publicKey: kp.publicKey });
    const r = await verifyTrustList(env, { pinnedPublishers: [other.key], nowSec: NOW });
    expect(r.ok).toBe(true);
    expect(r.pinned).toBe(false);
  });

  it("two versions of one list under two spellings are one publisher: the higher version wins", async () => {
    const { kp, kash, key } = await publisher();
    const v1 = await verifyTrustList(await signTrustList(listOf(kash, [], 1), { keyid: kash, privateKey: kp.privateKey, publicKey: kp.publicKey }), { pinnedPublishers: [kash], nowSec: NOW });
    const v2 = await verifyTrustList(await signTrustList(listOf(key, [], 2), { keyid: key, privateKey: kp.privateKey, publicKey: kp.publicKey }), { pinnedPublishers: [kash], nowSec: NOW });
    const current = currentTrustLists([v1, v2]);
    expect(current).toHaveLength(1);
    expect(current[0]!.version).toBe(2);
  });

  it("a self-listed issuer matches its signer across spellings", async () => {
    const { kp, kash } = await publisher();
    const issuer = await publisher();
    const env = await signTrustList(
      listOf(kash, [{ issuerId: issuer.kash, label: "self-listed", keys: [], dsts: ["application/vnd.oreoasis.work-record+json"], validFromUnix: WINDOW.validFromUnix, validUntilUnix: WINDOW.validUntilUnix }]),
      { keyid: kash, privateKey: kp.privateKey, publicKey: kp.publicKey },
    );
    const report = await verifyTrustList(env, { pinnedPublishers: [kash], nowSec: NOW });
    expect(report.ok).toBe(true);
    const match = findListing(issuer.key, "application/vnd.oreoasis.work-record+json", [report], NOW);
    expect(match?.pinned).toBe(true);
  });
});

describe("RW-19 B — the holder's resolution order", () => {
  it("a did:key keyid resolves at step 1, self-certifying, with its declared type", async () => {
    const { kash, key } = await publisher();
    const resolve = makeKeyResolver(new Map(), new Map());
    for (const keyid of [kash, key]) {
      const r = resolve(keyid);
      expect(r?.source).toBe("self-certifying");
      expect(r?.type).toBe("Ed25519");
    }
    expect(resolve(kash)!.publicKey).toEqual(resolve(key)!.publicKey);
  });
});
