/**
 * RW-19 B — a rule under a standard author identifier (d97(h); d91(e); RW-14 §1.1).
 *
 * A `did:web` organisation's rule reads offline only with its key handed in —
 * a pinned trust list's or a held one, never fetched — and the refusal
 * without one names exactly that. A self-certifying author reads from the
 * identifier alone, under either spelling: `did:kash` and `did:key` are two
 * spellings of one key, one author.
 */

import { describe, expect, test } from "bun:test";
import { toDidKey } from "@kashscript/identity-core";
import { internshipRule } from "../src/fixtures";
import { readRule, signRule, RuleError } from "../src/rule";
import { party } from "./world";

const WEB_AUTHOR = "did:web:campus.example";

describe("RW-19 B — a did:web author", () => {
  test("its rule reads with the key handed in, and the request names the did:web as the door", async () => {
    const campus = await party();
    const body = internshipRule({ campus: WEB_AUTHOR });
    const envelope = await signRule(body, { keyid: `${WEB_AUTHOR}#sig-1`, privateKey: campus.privateKey, publicKey: campus.publicKey });
    const rule = await readRule(envelope, {
      resolveKey: (keyid) => (keyid.split("#")[0] === WEB_AUTHOR ? { type: "Ed25519", publicKey: campus.publicKey } : null),
    });
    expect(rule.body.author).toBe(WEB_AUTHOR);
    expect(rule.body.id).toBe(`${WEB_AUTHOR}/rule/internship-credit`);
  });

  test("without a handed-in key it is refused, and the refusal says what to hand in", async () => {
    const campus = await party();
    const envelope = await signRule(internshipRule({ campus: WEB_AUTHOR }), { keyid: WEB_AUTHOR, privateKey: campus.privateKey, publicKey: campus.publicKey });
    expect(readRule(envelope)).rejects.toThrow(/did:web organisation.*resolveKey.*nothing is fetched/);
  });

  test("a handed-in key for the wrong keyid binds nothing", async () => {
    const campus = await party();
    const stranger = await party();
    const envelope = await signRule(internshipRule({ campus: WEB_AUTHOR }), { keyid: WEB_AUTHOR, privateKey: campus.privateKey, publicKey: campus.publicKey });
    expect(
      readRule(envelope, { resolveKey: (keyid) => (keyid === "did:web:another.example" ? { type: "Ed25519", publicKey: stranger.publicKey } : null) }),
    ).rejects.toThrow(RuleError);
  });
});

describe("RW-19 B — two spellings, one author", () => {
  test("a did:kash-authored rule signed under the key's did:key spelling reads from the identifier alone", async () => {
    const campus = await party();
    const body = internshipRule({ campus: campus.did });
    const envelope = await signRule(body, { keyid: toDidKey(campus.did), privateKey: campus.privateKey, publicKey: campus.publicKey });
    const rule = await readRule(envelope);
    expect(rule.body.author).toBe(campus.did);
  });

  test("and the mirror: a did:key-authored rule signed under the did:kash spelling", async () => {
    const campus = await party();
    const author = toDidKey(campus.did);
    const body = internshipRule({ campus: author });
    const envelope = await signRule(body, { keyid: campus.did, privateKey: campus.privateKey, publicKey: campus.publicKey });
    const rule = await readRule(envelope);
    expect(rule.body.author).toBe(author);
  });

  test("another key's spelling is still another author", async () => {
    const campus = await party();
    const other = await party();
    const body = internshipRule({ campus: campus.did });
    await expect(signRule(body, { keyid: toDidKey(other.did), privateKey: other.privateKey, publicKey: other.publicKey })).rejects.toThrow(
      "a rule is signed by its author's own key",
    );
  });
});
