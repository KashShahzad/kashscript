/**
 * The keystore: a key is made once, kept private to its owner, and never trusted
 * if its file says one DID and its key derives another (d47: never on a server).
 *
 * On Windows the owner-only check is made independently of the code under test —
 * by reading `icacls`'s plain output — so the test cannot pass by agreeing with itself.
 */

import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { userInfo } from "node:os";
import { join } from "node:path";
import { deriveDid, importKey } from "@kashscript/identity-core";

import { checkProtection, classifySddl, currentSid } from "../src/keystore/permissions";
import { createKey, fileIO, listKeys, loadKey, resolveKeyPath } from "../src/keystore/store";
import { KashCliError } from "../src/errors";
import { removeDir, tempDir } from "./helpers";

const WIN = process.platform === "win32";

/** icacls's own listing: one string per access entry (`NAME:(flags)`), read without any of our parsing. */
function icaclsEntries(path: string): string[] {
  const r = spawnSync("icacls", [path], { encoding: "utf8", windowsHide: true });
  expect(r.status).toBe(0);
  return (r.stdout ?? "").split(/\r?\n/).flatMap((line) => {
    // `DOMAIN\name:(OI)(CI)(F)` — an access entry is a name, a colon, and parenthesised flags.
    return /\S+:(\([A-Z,]+\))+\s*$/.test(line.trim()) ? [line.trim()] : [];
  });
}

describe("the keystore", () => {
  let root = "";
  beforeAll(() => {
    root = tempDir("keystore");
  });
  afterAll(() => removeDir(root));

  it("makes a key whose DID is the one its key derives, and loads it back", async () => {
    const ks = join(root, "a");
    const made = await createKey("station", ks);
    expect(made.did).toMatch(/^did:kash:/);
    expect(existsSync(made.path)).toBe(true);

    const file = JSON.parse(readFileSync(made.path, "utf8"));
    expect(file.format).toBe("kash-key/1");
    expect(file.did).toBe(made.did);
    expect<string>(deriveDid((await importKey(file.jwk)).publicKey)).toBe(made.did);

    const loaded = await loadKey("station", ks);
    expect(loaded.did).toBe(made.did);
    expect(loaded.privateKey.length).toBe(32);
  });

  it("never overwrites a key, and leaves the first one untouched", async () => {
    const ks = join(root, "b");
    const first = await createKey("station", ks);
    const before = readFileSync(first.path, "utf8");
    await expect(createKey("station", ks)).rejects.toMatchObject({ code: "KEY_EXISTS" });
    expect(readFileSync(first.path, "utf8")).toBe(before);
  });

  it("keeps the key file private to its owner — confirmed by the OS's own listing", async () => {
    const ks = join(root, "c");
    const made = await createKey("teacher", ks);
    expect(made.file.confirmed).toBe(true);
    expect(made.folder?.confirmed).toBe(true);

    if (WIN) {
      for (const path of [made.path, ks]) {
        const entries = icaclsEntries(path);
        expect(entries.length).toBe(1);
        expect(entries[0]!.toLowerCase()).toContain(`\\${userInfo().username.toLowerCase()}:`);
        expect(entries[0]).not.toContain("(I)"); // nothing inherited: no SYSTEM, no Administrators, no Users
      }
    } else {
      expect(statSync(made.path).mode & 0o077).toBe(0);
      expect(statSync(ks).mode & 0o077).toBe(0);
    }
  });

  it("does not call a file private when it is not", () => {
    // An ordinary file in the temp folder inherits the folder's wider access list.
    const loose = join(root, "loose.txt");
    writeFileSync(loose, "x");
    if (!WIN) chmodSync(loose, 0o644); // the POSIX equivalent of "others can read"
    expect(checkProtection(loose, "file").confirmed).toBe(false);
  });

  it("leaves a folder that already existed as it found it", async () => {
    const ks = join(root, "d");
    mkdirSync(ks, { recursive: true });
    const made = await createKey("station", ks);
    expect(made.folder).toBeNull();
    expect(made.file.confirmed).toBe(true); // the key file is private either way
  });

  it("refuses a key file whose DID is not the one its key derives", async () => {
    const ks = join(root, "e");
    const a = await createKey("one", ks);
    const b = await createKey("two", ks);
    const forged = JSON.parse(readFileSync(a.path, "utf8"));
    forged.did = b.did; // claim to be the other key
    writeFileSync(a.path, JSON.stringify(forged));
    await expect(loadKey("one", ks)).rejects.toMatchObject({ code: "KEY_INVALID" });
  });

  it("refuses a name that could walk out of the keystore, and a key that is not there", async () => {
    await expect(createKey("../escape", join(root, "f"))).rejects.toBeInstanceOf(KashCliError);
    await expect(createKey("", join(root, "f"))).rejects.toBeInstanceOf(KashCliError);
    await expect(loadKey("nobody", join(root, "f"))).rejects.toMatchObject({ code: "KEY_NOT_FOUND" });
  });

  it("treats a bare name as a keystore entry and a path as itself", () => {
    const ks = join(root, "g");
    expect(resolveKeyPath("station", ks)).toBe(join(ks, "station.key.json"));
    expect(resolveKeyPath(join(root, "x", "k.key.json"), ks)).toBe(join(root, "x", "k.key.json"));
  });

  it("refuses to sign with a key other accounts can use, on every platform — and says how to fix it", async () => {
    const ks = join(root, "exposed");
    const made = await createKey("station", ks);
    expect((await loadKey("station", ks)).did).toBe(made.did); // private: loads
    if (WIN) {
      // BUILTIN\Users (S-1-5-32-545) given read access
      const r = spawnSync("icacls", [made.path, "/grant", "*S-1-5-32-545:R"], { encoding: "utf8", windowsHide: true });
      expect(r.status).toBe(0);
    } else {
      chmodSync(made.path, 0o644);
    }
    expect(checkProtection(made.path, "file").state).toBe("exposed");
    await expect(loadKey("station", ks)).rejects.toMatchObject({ code: "KEY_UNPROTECTED" });
    await expect(loadKey("station", ks)).rejects.toThrow(WIN ? /icacls/ : /chmod 600/);
  });

  it.skipIf(!WIN)("a key that is the owner's only by inheritance is 'unknown': it loads, but is not called confirmed", async () => {
    const ks = join(root, "inherited");
    const made = await createKey("station", ks);
    const r = spawnSync("icacls", [made.path, "/reset"], { encoding: "utf8", windowsHide: true }); // back to the folder's inherited entries
    expect(r.status).toBe(0);
    const p = checkProtection(made.path, "file");
    expect(p.confirmed).toBe(false);
    expect(p.state).not.toBe("private");
    expect((await loadKey("station", ks)).did).toBe(made.did);
  });

  it("reads an ACL as the OS writes it: the owner's SID or its short names, SYSTEM and Administrators tolerated, anyone else not", () => {
    const me = "S-1-5-21-111-222-333-1001";
    const mine = `(A;;FA;;;${me})`;
    expect(classifySddl(`D:PAI${mine}`, me).state).toBe("private");
    expect(classifySddl(`D:PAI(A;OICI;FA;;;${me})`, me).state).toBe("private");
    // the built-in Administrator account (RID 500) is written `LA`
    expect(classifySddl("D:PAI(A;;FA;;;LA)", "S-1-5-21-111-222-333-500").state).toBe("private");
    expect(classifySddl("D:PAI(A;;FA;;;LA)", me).state).toBe("exposed");
    // the default inherited list: owner, SYSTEM, Administrators — usable only by them, but not locked to the owner
    const inherited = classifySddl(`D:(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;${me})`, me);
    expect(inherited.state).toBe("unknown");
    expect(inherited.confirmed).toBe(false);
    // anyone else, however it is spelled
    for (const other of ["WD", "BU", "AU", "IU", "S-1-5-21-111-222-333-1002"]) {
      expect(classifySddl(`D:PAI${mine}(A;;FR;;;${other})`, me).state).toBe("exposed");
    }
    // a deny entry grants nothing
    expect(classifySddl(`D:PAI(D;;FR;;;WD)${mine}`, me).state).toBe("private");
  });

  it("takes a key's name from its file name, never from what the file says (it is shown to a person deciding to sign)", async () => {
    const ks = join(root, "named");
    const made = await createKey("station", ks);
    const file = JSON.parse(readFileSync(made.path, "utf8"));
    file.name = "\u001b[31mTHE-REAL-STATION";
    writeFileSync(made.path, JSON.stringify(file));
    expect((await loadKey("station", ks)).name).toBe("station");
    // A POSIX file name may hold a control character (Windows refuses to create one): it is shown as "?".
    if (!WIN) {
      const odd = join(root, "named", "bad\u001bname.key.json");
      writeFileSync(odd, readFileSync(made.path, "utf8"));
      chmodSync(odd, 0o600);
      expect((await loadKey(odd)).name).toBe("bad?name");
    }
    // …and a name outside plain ASCII is shown with "?" too, so no escape sequence or look-alike can pass for a label
    const unicode = join(root, "named", "statiön.key.json");
    writeFileSync(unicode, readFileSync(made.path, "utf8"));
    if (!WIN) chmodSync(unicode, 0o600);
    else spawnSync("icacls", [unicode, "/inheritance:r", "/grant:r", `*${currentSid()}:F`], { windowsHide: true });
    expect((await loadKey(unicode)).name).toBe("stati?n");
  });

  it("takes away the empty file when the secret cannot be written, so the name is not blocked for good", async () => {
    const ks = join(root, "failing");
    const real = fileIO.writeSecret;
    fileIO.writeSecret = () => {
      throw new Error("disk full (simulated)");
    };
    try {
      await expect(createKey("station", ks)).rejects.toThrow(/Nothing was left behind/);
    } finally {
      fileIO.writeSecret = real;
    }
    expect(existsSync(join(ks, "station.key.json"))).toBe(false);
    // and the same name can be made afterwards
    expect((await createKey("station", ks)).did).toMatch(/^did:kash:/);
  });

  it("lists keys with their DIDs and whether each is still private", async () => {
    const ks = join(root, "h");
    const a = await createKey("alpha", ks);
    await createKey("beta", ks);
    const listed = listKeys(ks);
    expect(listed.map((k) => k.name)).toEqual(["alpha", "beta"]);
    expect(listed[0]!.did).toBe(a.did);
    expect(listed.every((k) => k.protection.confirmed)).toBe(true);
    expect(listKeys(join(root, "nowhere"))).toEqual([]);
  });
});
