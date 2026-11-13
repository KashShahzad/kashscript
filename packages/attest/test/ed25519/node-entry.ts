/**
 * The Ed25519 verdicts under plain Node: bundled by test/ed25519-vectors.test.ts
 * with `bun build --target node`, run with the three vector files as arguments,
 * and compared with the pinned verdicts. Node's WebCrypto is OpenSSL's; bun's
 * and Chromium's are BoringSSL's. The rule makes them answer alike.
 */

import { readFileSync } from "node:fs";
import { ed25519Verdicts, type GeneratedFile, type SpeccheckCase, type WycheproofFile } from "./verdicts";

const [wy, sc, gen] = process.argv.slice(2);
const read = (p: string | undefined): unknown => JSON.parse(readFileSync(p!, "utf8"));
ed25519Verdicts({ wycheproof: read(wy) as WycheproofFile, speccheck: read(sc) as SpeccheckCase[], generated: read(gen) as GeneratedFile })
  .then((v) => {
    process.stdout.write(JSON.stringify(v));
  })
  .catch((e: unknown) => {
    process.stderr.write(String(e instanceof Error ? e.stack ?? e.message : e));
    process.exit(2);
  });
