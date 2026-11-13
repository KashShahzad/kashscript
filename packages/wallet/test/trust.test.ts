import { currentTrustLists, findListing } from "@kashscript/attest/holder";
import { describe, expect, test } from "bun:test";
import { PREDICATE_VCT } from "@kashscript/attest/exchange";
import { PracticePublisher } from "../src/headless";
import { PRACTICE_RECORD_DST } from "../src/headless/practice/issuer";
import { practiceWorld } from "./helpers";

describe("trust lists — a list is its publisher's own", () => {
  test("a higher-numbered list of the same id from a publisher nobody pinned never replaces the pinned one", async () => {
    const w = await practiceWorld("trust-evict");
    const stranger = await PracticePublisher.create(w.now);
    const entry = { did: w.issuer.did, label: "an issuer", dsts: [PRACTICE_RECORD_DST, PREDICATE_VCT] };
    await stranger.list([entry]);
    await stranger.list([entry]);
    const theirs = await stranger.list([]); // the same list id, version 3, naming nobody

    const kept = await w.wallet.trust.add(theirs);
    expect(kept.ok).toBe(true);
    expect(kept.pinned).toBe(false);

    const reports = await w.wallet.trust.reports();
    expect(reports.filter((r) => r.pinned).map((r) => r.version)).toEqual([1]); // the pinned list is still there
    expect(reports.filter((r) => !r.pinned).map((r) => r.version)).toEqual([3]); // and theirs is only their word

    const current = currentTrustLists((await w.wallet.trust.reports()).filter((r) => r.pinned));
    expect(current.map((r) => [r.version, r.pinned])).toEqual([[1, true]]);

    const match = findListing(w.issuer.did, PRACTICE_RECORD_DST, reports, w.now());
    expect(match?.pinned).toBe(true);
  });

  test("the pinned publisher's own newer list still replaces its older one, and an older one never replaces a newer", async () => {
    const w = await practiceWorld("trust-versions");
    const entry = { did: w.issuer.did, label: w.issuer.name, dsts: [PRACTICE_RECORD_DST, PREDICATE_VCT] };
    const v2 = await w.publisher.list([entry]);
    const v3 = await w.publisher.list([]);
    await w.wallet.trust.add(v3);
    const back = await w.wallet.trust.add(v2); // an older number arrives later
    expect(back.version).toBe(3);
    expect((await w.wallet.trust.reports()).map((r) => r.version)).toEqual([3]);
  });
});
