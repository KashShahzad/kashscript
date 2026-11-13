# Security policy

This is the security policy of all five repositories of the Indorania ecosystem — Indorania,
KashScript, Oreoasis, Duedale and Indusland. The text is the same in each. What is specific to a
repository (its scope notes and its stamped security baseline) is in that repository's
[docs/security/baseline.md](docs/security/baseline.md).

These systems issue and check records that other people rely on. A flaw here is not an
inconvenience: it can be someone's proof. Reports are welcome and taken seriously.

**Contact: r.kashifshahzad@outlook.com** — one human reads that inbox. Use the subject `SECURITY`.
Each site publishes the same address in its `/.well-known/security.txt` (RFC 9116).

## Reporting

Email the address above with what you found, how to reproduce it, which repository, package or site
it affects, and how you would like to be credited. Please do not open a public issue or pull request
for anything exploitable.

No public encryption key is published yet. If you want to encrypt, say so in a first short message
and we will send one.

- **Acknowledgement:** within 2 business days.
- **Assessment and a plan:** within 5 business days.
- **Fix:** as fast as the severity demands; you will hear a timeline, not silence.
- **Disclosure:** coordinated. Tell us when you intend to publish and we will work to that date
  rather than argue about it. We credit you unless you would rather we did not.

This is a small operation. These are commitments we can keep, not enterprise SLA language.

## Safe harbour

We will not pursue legal action against, or ask a platform or law enforcement to act against,
anyone doing good-faith research within this policy:

- Test only against your own accounts, organisations, books, keys and receipts.
- Do not access, modify or exfiltrate other people's or organisations' data. If you can prove a
  cross-tenant flaw with one record, stop there and tell us.
- No denial of service, no spam, no social engineering of the founder, customers or vendors, and no
  physical attacks.
- Give us a reasonable window before publishing.

## In scope

- **Indorania** — `@indorania/*` (the contracts, tokens, ui, the platform packages, the portal,
  Chakor), and indorania.org.
- **KashScript** — `@kashscript/*` on npm, the registry service, and kashscript.com with its
  subdomains.
- **Oreoasis** — the API at `api.oreoasis.com`, the proof and approval pages, `@oreoasis/sdk`, and
  oreoasis.com.
- **Duedale** — the desk and the book, and duedale.com.
- **Indusland** — the web and mobile apps, their workers, and indusland.xyz.

Not in scope: demo and preview deployments, practice-mode assertions and seeded keys that are
labelled as practice.

## What we especially want to hear about

- **Cross-tenant access** — any read or write reaching another organisation's receipts, keys,
  books, exports or dashboards. This is the class we consider most damaging.
- **Signature or chain forgery** — anything that makes a tampered record verify, lets a chain be
  rewritten or reordered, or breaks an append-only log.
- **Verification integrity** — a proof page, checker or verify endpoint that states a verdict its
  underlying proof does not support, and injection through fields derived from a record (customer
  content is hostile input).
- **Authentication and keys** — sign-in or passkey bypass, session forgery, privilege escalation,
  and any exposure of an organisation's or the platform's signing key.
- **Surveillance by accident** — anything that lets a caller list, search, count or follow people
  across relationships, or export records in bulk, which the floor forbids.

## Out of scope

Reports with no security impact: missing security headers on static marketing pages,
rate-limiting on unauthenticated marketing forms, advice on email authentication we have already
scheduled, clickjacking on pages with no state-changing action, self-XSS, outdated-library reports
without a demonstrated path to exploitation, and automated-scanner output with no analysis
attached.

## No bug bounty (yet)

There is no money in the programme today, and we will not imply otherwise. What we offer is a fast
human reply, credit where you want it, and a public fix. If a report is genuinely serious, ask —
we would rather negotiate a payment than pretend the finding was not worth one.
