// The door's evaluator in a browser build: read the signed rule, check it
// against the person's receipts, check the packet as the desk would, and route.
// The vectors come in the page; nothing is fetched.

import { checkPacket, checklist, readRule, route } from "../../src";

declare const document: { getElementById(id: string): { textContent: string | null } | null };
declare const navigator: { userAgent: string };

(async () => {
  const out = document.getElementById("out")!;
  try {
    const v = JSON.parse(document.getElementById("vectors")!.textContent!);
    const rule = await readRule(v.rule);
    const list = await checklist(rule, v.held, { asOf: v.asOf, trustLists: v.trustLists, ownWord: v.ownWord });
    const check = await checkPacket({ rule, request: v.request, vp_token: v.vp_token, ctx: { trustLists: v.trustLists }, asOf: v.asOf });
    const routed = await route(rule, check, { asOf: v.asOf });
    out.textContent = JSON.stringify({
      userAgent: navigator.userAgent,
      rows: list.rows.map((r) => [r.criterion, r.state]),
      ready: list.ready,
      problems: check.problems,
      route: routed.route,
      fired: [...routed.fired].sort(),
    });
  } catch (e) {
    out.textContent = JSON.stringify({ crashed: String(e) });
  }
})();
