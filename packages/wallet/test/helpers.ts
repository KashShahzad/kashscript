import { join } from "node:path";
import { readFileSync } from "node:fs";
import { createHeadlessWallet, PracticeIssuer, PracticeNetwork, PracticePublisher, PracticeVerifier, PracticeEstablishment, PRACTICE_T0 } from "../src/headless";
import { PREDICATE_VCT, THANK_YOU_VCT } from "@kashscript/attest/exchange";
import { PRACTICE_RECORD_DST } from "../src/headless/practice/issuer";

export const VECTORS = join(import.meta.dir, "..", "..", "attest", "test", "vectors");
export const readVector = (path: string): string => readFileSync(join(VECTORS, path), "utf8");

export const hex = (s: string): Uint8Array => Uint8Array.from(s.match(/../g)!.map((b) => parseInt(b, 16)));

/** A practice world: a pinned publisher, a listed issuer, a café, two verifiers, and a person's headless wallet. */
export async function practiceWorld(seed = "test") {
  const clock = { t: PRACTICE_T0 };
  const now = () => clock.t;
  const net = new PracticeNetwork();
  const publisher = await PracticePublisher.create(now);
  const issuer = await PracticeIssuer.create({ origin: "https://records.practice.invalid", name: "A practice records desk", now });
  const cafe = await PracticeEstablishment.create({ origin: "https://cafe.practice.invalid", name: "A practice café", now });
  const verifier = await PracticeVerifier.create({ origin: "https://verifier.practice.invalid", name: "A practice insurer", now });
  const other = await PracticeVerifier.create({ origin: "https://other.practice.invalid", name: "A practice buyer", now });
  for (const x of [issuer, cafe.issuer]) net.mount(x.origin, x.handler);
  for (const v of [verifier, other]) net.mount(v.origin, v.handler);
  const person = await createHeadlessWallet({ practice: true, seed, now, transport: net.transport, pinnedPublishers: [publisher.did] });
  await person.wallet.trust.add(
    await publisher.list([
      { did: issuer.did, label: issuer.name, dsts: [PRACTICE_RECORD_DST, PREDICATE_VCT] },
      { did: cafe.issuer.did, label: cafe.name, dsts: [THANK_YOU_VCT] },
    ]),
  );
  return { clock, now, net, publisher, issuer, cafe, verifier, other, person, wallet: person.wallet };
}

export type World = Awaited<ReturnType<typeof practiceWorld>>;

/** Receive the practice visit record and a batch of copies of a yes. */
export async function receiveYes(w: World): Promise<void> {
  await w.wallet.proof.set(w.issuer.origin, "on", w.issuer.name);
  const r = await w.wallet.receive.accept(await w.wallet.receive.open(w.issuer.offer(["practice-visit", "practice-yes"])));
  if (r.status !== "stored") throw new Error(`receive: ${r.status}`);
}
