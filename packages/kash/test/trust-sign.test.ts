/**
 * `kash trust sign` — the founder signs a trust or status list with the publisher
 * key, in the wallet's own format, and nothing is uploaded (d62(d)5).
 *
 * The signed output is checked by attest's published binary (`kash verify`), and the
 * node runs sit under the offline guard.
 */

import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { DST_WORK_RECORD, STATUS_LIST_FORMAT, STATUS_LIST_MIN_ENTRIES, TRUST_LIST_FORMAT, encodeStatusList } from "@kashscript/attest";

import { bunSrc, buildBundles, didFrom, nodeDist, removeDir, tempDir, type Runner } from "./helpers";

const NOW = Math.floor(Date.now() / 1000);
const DAY = 86_400;

let keystore = "";
let work = "";
let publisher = "";
let issuer = "";

beforeAll(() => {
  buildBundles();
  keystore = join(tempDir("trust-keys"), "keystore");
  work = tempDir("trust-work");
  publisher = didFrom(bunSrc(["station", "init", "--name", "publisher", "--keystore", keystore]).stdout);
  issuer = didFrom(bunSrc(["station", "init", "--name", "station", "--keystore", keystore]).stdout);
}, 180_000);
afterAll(() => {
  removeDir(keystore);
  removeDir(work);
});

/** A trust list payload as the founder would write it — no `publisher`, no signature. */
function trustList(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    format: TRUST_LIST_FORMAT,
    listId: "station-zero-simulation",
    version: 1,
    issuedAtUnix: NOW,
    validFromUnix: NOW - DAY,
    validUntilUnix: NOW + 365 * DAY,
    issuers: [
      {
        issuerId: issuer,
        label: "Station zero (simulation)",
        keys: [],
        dsts: [DST_WORK_RECORD],
        validFromUnix: NOW - DAY,
        validUntilUnix: NOW + 365 * DAY,
      },
    ],
    ...over,
  };
}

function write(name: string, value: unknown): string {
  const path = join(work, name);
  writeFileSync(path, typeof value === "string" ? value : JSON.stringify(value, null, 2));
  return path;
}

for (const [label, run] of [["bun-src", bunSrc], ["node-dist", nodeDist]] as ReadonlyArray<readonly [string, Runner]>) {
  describe(`trust sign — ${label}`, () => {
    it("prints only the signed file, which attest verifies — and pins to the publisher", () => {
      const file = write(`list-${label}.json`, trustList());
      const signed = run(["trust", "sign", file, "--keystore", keystore]);
      expect(signed.stderr).not.toContain("offline-guard");
      expect(signed.status).toBe(0);

      // stdout is the envelope and nothing else, so it pipes
      const envelope = JSON.parse(signed.stdout);
      expect(envelope.payloadType).toBe("application/vnd.kash.trust-list+json");
      expect(envelope.signatures.length).toBe(1);
      expect(envelope.signatures[0].keyid).toBe(publisher);
      const payload = JSON.parse(Buffer.from(envelope.payload, "base64").toString("utf8"));
      expect(payload.publisher).toBe(publisher); // filled in from the key
      expect(payload.issuers[0].issuerId).toBe(issuer);

      const signedFile = write(`signed-${label}.json`, signed.stdout);
      const pinned = run(["verify", signedFile, "--trust-publisher", publisher]);
      expect(pinned.stderr).not.toContain("offline-guard");
      expect(pinned.stdout).toContain(`publisher          : ${publisher} — pinned`);
      expect(pinned.stdout).toContain("RESULT: PASS");
      expect(pinned.status).toBe(0);

      // not pinned, the same list is only its publisher's word, and says so
      const unpinned = run(["verify", signedFile]);
      expect(unpinned.stdout).toContain("NOT pinned");
      expect(unpinned.status).toBe(0);
    }, 120_000);

    it("a list that has been altered after signing fails", () => {
      const file = write(`alter-${label}.json`, trustList());
      const envelope = JSON.parse(run(["trust", "sign", file, "--keystore", keystore]).stdout);
      const payload = JSON.parse(Buffer.from(envelope.payload, "base64").toString("utf8"));
      payload.issuers[0].label = "Someone else";
      envelope.payload = Buffer.from(JSON.stringify(payload)).toString("base64");
      const r = run(["verify", write(`altered-${label}.json`, envelope), "--trust-publisher", publisher]);
      expect(r.stdout).toContain("RESULT: FAIL");
      expect(r.status).toBe(1);
    }, 120_000);

    it("signs a status list of the minimum size, and it verifies", async () => {
      const encodedList = await encodeStatusList(new Uint8Array(STATUS_LIST_MIN_ENTRIES / 8));
      const file = write(`status-${label}.json`, {
        format: STATUS_LIST_FORMAT,
        type: "BitstringStatusList",
        id: "https://lists.example/station-zero/revocation/1",
        statusPurpose: "revocation",
        encodedList,
        issuedAtUnix: NOW,
        validUntilUnix: NOW + 30 * DAY,
      });
      const signed = run(["trust", "sign", file, "--keystore", keystore]);
      expect(signed.status).toBe(0);
      expect(JSON.parse(signed.stdout).payloadType).toBe("application/vnd.kash.status-list+json");
      const r = run(["verify", write(`status-signed-${label}.json`, signed.stdout)]);
      expect(r.stdout).toContain("Status list");
      expect(r.stdout).toContain("RESULT: PASS");
      expect(r.status).toBe(0);
    }, 120_000);
  });
}

describe("trust sign — what it refuses (and prints nothing for)", () => {
  const refuse = (name: string, body: unknown, expectInStderr: string, extra: readonly string[] = []): void => {
    const r = bunSrc(["trust", "sign", write(name, body), "--keystore", keystore, ...extra]);
    expect(r.status).toBe(1);
    expect(r.stdout).toBe("");
    expect(r.stderr).toContain(expectInStderr);
  };

  it("a list that names another publisher", () => {
    refuse("other-publisher.json", trustList({ publisher: issuer }), "KEY_INVALID");
  });

  it("an issuer granted a tag that is not registered", () => {
    const list = trustList();
    (list["issuers"] as Array<Record<string, unknown>>)[0]!["dsts"] = ["application/vnd.made-up+json"];
    refuse("unregistered.json", list, "RECORD_INVALID");
  });

  it("a status list below the size floor", async () => {
    refuse("tiny-status.json", {
      format: STATUS_LIST_FORMAT,
      type: "BitstringStatusList",
      id: "https://lists.example/tiny",
      statusPurpose: "revocation",
      encodedList: await encodeStatusList(new Uint8Array(8)),
      issuedAtUnix: NOW,
      validUntilUnix: null,
    }, "RECORD_INVALID");
  });

  it("a file that is already signed, one that is not a list, and one that is not JSON", () => {
    refuse("already.json", { payloadType: "x", payload: "e30=", signatures: [] }, "already a signed envelope");
    refuse("not-a-list.json", { format: "something-else/1" }, "Not a list kash signs");
    const notJson = bunSrc(["trust", "sign", write("bad.json", "{{{"), "--keystore", keystore]);
    expect(notJson.status).toBe(1);
    expect(notJson.stdout).toBe("");
  });

  it("the station's key is not the publisher's: with no publisher key it stops, rather than falling back", () => {
    const lonely = join(tempDir("lonely"), "ks");
    expect(bunSrc(["station", "init", "--name", "station", "--keystore", lonely]).status).toBe(0);
    const r = bunSrc(["trust", "sign", write("lonely.json", trustList()), "--keystore", lonely]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("KEY_NOT_FOUND");
    expect(r.stdout).toBe("");
    removeDir(join(lonely, ".."));
  });

  it("--out writes the same bytes it prints, and will not overwrite", () => {
    const out = join(work, "out.json");
    const file = write("for-out.json", trustList());
    const first = bunSrc(["trust", "sign", file, "--keystore", keystore, "--out", out]);
    expect(first.status).toBe(0);
    expect(readFileSync(out, "utf8")).toBe(first.stdout);
    const again = bunSrc(["trust", "sign", file, "--keystore", keystore, "--out", out]);
    expect(again.status).toBe(1);
    expect(again.stdout).toBe("");
    expect(existsSync(out)).toBe(true);
  });
});
