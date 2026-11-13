# Contributing to KashScript

This page is the same in all five repositories of the Indorania ecosystem (Indorania, KashScript,
Oreoasis, Duedale, Indusland), except the section on what carries which licence.

## Sign the CLA first

**No outside code is merged without a signed contributor licence agreement** (ecosystem decision
87(c)). Some of this code is open and some is private for now and may later be opened under
AGPL-3.0 with a commercial licence beside it, so we need your permission to use a contribution
under any of those licences. [CLA.md](CLA.md) is that agreement, in plain words. **You keep your
copyright; you give us a licence.** It is a draft a lawyer has not yet read, so until one has, we may
decline any contribution.

**How to sign.** Email **r.kashifshahzad@outlook.com** with the subject `CLA`, containing:

1. this sentence, unchanged: *"I have read the Indorania ecosystem Contributor Licence Agreement,
   version 1.0, and I agree to it for my past and future contributions to its repositories."*
2. your full legal name, your GitHub handle, and the repository you are contributing to;
3. if an employer, university or client could claim your work, say so — we need their written
   agreement first.

The founder keeps the register privately; your name is not published in the repository. A pull
request is merged only after the founder has recorded "CLA on file" on it. You sign once for all
five repositories.

## How a change is proposed

- **Open an issue first** for anything beyond a small fix, so we can say early whether it fits.
  Issues, bug reports and discussion need no CLA.
- **One purpose per pull request**, small enough to read. Say what changes and why, and what you
  ran to check it.
- **Typecheck, lint and the tests must be green**; a change to behaviour comes with a test.
- **Match the repository** — its `CLAUDE.md` and `README.md` say how it is built and what it never
  does. Do not add dependencies, services or new public names without agreeing them in the issue.
- **Anything exploitable goes to [SECURITY.md](SECURITY.md)**, never to a public issue or pull
  request.
- We may decline a contribution for any reason, and we say why.

## The floor binds contributions

Every contribution is held to the ecosystem's floor, however well built it is. A change that breaks
one of these is declined:

- **Nothing searches for, lists, ranks, scores, profiles or follows a person.** No directory of
  people, no lookup, no refusal query, no bulk export, no cross-relationship joins.
- **A record is checked by presentation, and checking never needs us.** Verification stays free,
  offline-capable and in the open formats.
- **A machine may say yes or "not yet"; only a named person says no.** No AI sits in the decision
  path about a person; every decision names its rule's version and its reasons.
- **A decline leaves no trace, and every door keeps another way.** No door contacts someone who has
  not come to it; no one is made to take part for basic needs or rights.
- **A rule asks only for its purpose** — never an ascribed identity, a proxy for one, a sensitive
  category, or a refusal.
- **No activity surveillance:** no attendance or screen tracking, conformance percentages, personal
  error counts or rankings. Connectors capture artefacts and events, never activity.
- **No money moves through our code**, no custody, no payment gateway, no token.
- **Keys stay with whoever signs.** No person's key on a server; separate identifiers per
  relationship.
- **Never** ads, data sales, paid placement, per-record fees or engagement tricks.

These come from the project's decision log (the constitution, decisions 26–28, 41, 43 and 49, and
the floor of decisions 84 and 85). Ask in your issue and we will send the decisions a change
touches.

## What carries which licence (decision 87)

Everything in this repository is open. The test that put it here: if checking a record, or the
person's wallet, needs a package, it is Apache-2.0. Each of the twelve packages carries its own
Apache-2.0 `LICENSE`. The specification text and the rulebooks are CC BY 4.0, and the rest is
Apache-2.0, as the root [LICENSE](LICENSE) says. `scripts/check-boundary.ts` fails the build when a
package's `license`, `publishConfig`, `repository` or `LICENSE` file is wrong, and
`scripts/check-public-tree.ts` fails it when a closed or private path is added. The engines' servers
and the apps are developed elsewhere and are not open. A contribution here never needs them. The
copyright stays with the founder until the company is registered (decision 68).

## Publishing

Only the founder publishes, and only through [`.github/workflows/publish.yml`](.github/workflows/publish.yml)
(trusted publishing with provenance; [`docs/publishing.md`](docs/publishing.md)). A pull request
never bumps a version or publishes.
