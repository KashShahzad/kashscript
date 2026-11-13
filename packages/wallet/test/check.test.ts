import { describe, expect, test } from "bun:test";
import { isWalletError } from "../src/errors";
import { practiceWorld, readVector, receiveYes } from "./helpers";

describe("check — anyone's receipt, free, offline, and never a bare tick", () => {
  test("PL-3's complete session reads as signed by both; the pending one as not proof yet", async () => {
    const { wallet } = await practiceWorld("check");
    const complete = await wallet.check(JSON.parse(readVector("exchange/session-receipt-complete.v1.json")));
    expect(complete.state).toBe("signed-by-both");
    expect(complete.notProven).toContain("doesn't show that what it says is true");
    expect(complete.report.attestation).toBe("countersigned");
    const pending = await wallet.check(JSON.parse(readVector("exchange/session-receipt-pending.v1.json")));
    expect(pending.state).toBe("one-signature");
    expect(pending.words[0]).toContain("isn't proof");
  });

  test("a changed record doesn't match; every result says what it does not prove", async () => {
    const w = await practiceWorld("check-2");
    await receiveYes(w);
    const [visit] = (await w.wallet.records.list()).filter((e) => e.artifact.kind === "kash-event");
    const good = await w.wallet.check(visit!.artifact.value);
    expect(good.state).toBe("signed");
    expect(good.listed).toBe(true);
    expect(good.practice).toBe(true);
    expect(good.notProven.length).toBeGreaterThan(0);
    const changed = structuredClone(visit!.artifact.value) as { body: { what: string } };
    changed.body.what = "something else";
    const bad = await w.wallet.check(changed);
    expect(bad.state).toBe("doesnt-match");
    expect(bad.notProven.length).toBeGreaterThan(0);
  });

  test("checking works locked, with no lists — and needs no network at all", async () => {
    const w = await practiceWorld("check-3");
    w.wallet.lock();
    const sent = w.person.inspect.traffic().length;
    const r = await w.wallet.check(JSON.parse(readVector("exchange/session-receipt-complete.v1.json")));
    expect(r.state).toBe("signed-by-both");
    expect(r.listed).toBe(false);
    expect(w.person.inspect.traffic().length).toBe(sent);
    expect(isWalletError(await w.wallet.check("not an artifact").catch((e) => e), "REQUEST_INVALID")).toBe(true);
  });
});
