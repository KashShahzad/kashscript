import { describe, expect, test } from "bun:test";
import { verifyHolderExport } from "@kashscript/attest/holder";
import { createHeadlessWallet } from "../src/headless";
import { isWalletError } from "../src/errors";
import { practiceWorld, readVector, receiveYes } from "./helpers";

// PL-1's vectors: exported 2026-09-24, their trust list's publisher named in the vectors README.
const VECTOR_TIME = 1_790_208_000;
const VECTOR_PUBLISHER = "did:kash:CJyXiKAaH3EeBHm4ympbXJPBNE4JoTuA4QYVvRS5u3CT";
const BACKUP_PASSPHRASE = "test vector only — never a real backup";

const vectorWallet = (seed: string, at = VECTOR_TIME + 60) =>
  createHeadlessWallet({ practice: true, seed, now: () => at, pinnedPublishers: [VECTOR_PUBLISHER] });

describe("export and import — the holder contract's bundle", () => {
  test("imports PL-1's twelve-record export untouched, and exports it again as a file attest passes", async () => {
    const { wallet } = await vectorWallet("vectors");
    const text = readVector("holder/holder-export.v1.json");
    const result = await wallet.importAll(text);
    expect(result.records + result.dropped).toBe(12);
    expect(result.records).toBeGreaterThan(0);
    const again = await wallet.exportAll();
    const report = await verifyHolderExport(JSON.parse(again.text), { pinnedPublishers: [VECTOR_PUBLISHER], nowSec: VECTOR_TIME + 60, rawText: again.text });
    expect(report.ok).toBe(true);
    expect(report.canonical).toBe(true);
    // Every artifact is carried byte for byte — records stay what they are.
    const original = JSON.parse(text).records as { manifest: { recordId: string }; artifact: unknown }[];
    for (const r of JSON.parse(again.text).records as typeof original) {
      expect(JSON.stringify(r.artifact)).toBe(JSON.stringify(original.find((o) => o.manifest.recordId === r.manifest.recordId)!.artifact));
    }
  });

  test("the backup vector's keys come back only with the passphrase", async () => {
    const text = readVector("holder/holder-export-backup.v1.json");
    const locked = await (await vectorWallet("backup-a")).wallet.importAll(text);
    expect(locked.keysRestored).toBe(0);
    expect(locked.keysLeftLocked).toBe(true);
    const opened = await (await vectorWallet("backup-b")).wallet.importAll(text, { passphrase: BACKUP_PASSPHRASE });
    expect(opened.keysRestored).toBe(2);
    const wrong = await (await vectorWallet("backup-c")).wallet.importAll(text, { passphrase: "wrong passphrase" }).catch((e) => e);
    expect(isWalletError(wrong, "BACKUP_PASSPHRASE")).toBe(true);
  });

  test("an import made after a record's retention drops it — an export never resurrects a deleted record", async () => {
    const text = readVector("holder/holder-export.v1.json");
    const expiries = (JSON.parse(text).records as { manifest: { expiresAtUnix: number | null } }[]).map((r) => r.manifest.expiresAtUnix).filter((x): x is number => x !== null).sort((a, b) => a - b);
    const { wallet } = await vectorWallet("later", expiries[0]! + 1);
    const result = await wallet.importAll(text);
    expect(result.dropped).toBe(1);
    expect(result.records).toBe(11);
    expect((await wallet.exportAll()).text.includes(`"expiresAtUnix":${expiries[0]}`)).toBe(false);
  });

  test("a damaged file brings in nothing", async () => {
    const { wallet, inspect } = await vectorWallet("damaged");
    const before = inspect.snapshot();
    const text = readVector("holder/holder-export.v1.json").replace(/"receivedAtUnix":(\d+)/, (_, n) => `"receivedAtUnix":${Number(n) + 1}`);
    const tampered = JSON.parse(text);
    tampered.records[0].artifact = { kind: tampered.records[0].artifact.kind, value: tampered.records[1].artifact.value };
    expect(isWalletError(await wallet.importAll(JSON.stringify(tampered)).catch((e) => e), "IMPORT_INVALID")).toBe(true);
    expect(inspect.snapshot()).toBe(before);
  });

  test("the switch and the relationships stay behind; the log's copy assignments travel", async () => {
    const w = await practiceWorld("switch-stays");
    await receiveYes(w);
    await w.wallet.present.yes(await w.wallet.present.open(await w.verifier.request(w.verifier.ask("ask:practice-before-move"))));
    const file = await w.wallet.exportAll({ passphrase: "a practice passphrase" });
    expect(file.text.includes('"proof"')).toBe(false);
    for (const r of await w.wallet.relationships.list()) {
      expect(file.text.includes(r.mailbox)).toBe(false);
      expect(file.text.includes(r.id)).toBe(false);
    }
    const next = await createHeadlessWallet({ practice: true, seed: "next phone", now: w.now, transport: w.net.transport, pinnedPublishers: [w.publisher.did] });
    await next.wallet.importAll(file.text, { passphrase: "a practice passphrase" });
    expect(await next.wallet.proof.get(w.issuer.origin)).toBe("unset");
    const shown = (await next.wallet.records.list()).filter((e) => e.local.assignedVerifier === w.verifier.did);
    expect(shown.length).toBe(1);
  });
});
