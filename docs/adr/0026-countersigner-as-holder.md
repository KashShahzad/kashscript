# ADR-0026: A door's rule may name a countersigned record's holder as its countersigner — the one key whose acceptance verifies — and one function reads the holder for the desk, the wallet and the decision

- **Status:** Accepted (KS-Q11, built 2026-11-08; published under `alpha` by the founder)
- **Date:** 2026-11-08
- **Decision drivers:** ECOSYSTEM d26 (the other party signs), d41 (separate identifiers per relationship), d62(d)3 (no two verifiers get the same holder key), d84(a) (the subject keeps the receipt and shows it by choice), d91(a) (a receipt is the other side's acceptance)

## Context

A `kash-artifact` presentation is bound by a KB-style JWS that the record's holder signs. Until now the holder was the key at the query's `holder_path` in the signed payload, or else the countersign bundle's requester. That fits Client Sign-off: the doer writes the record, asks the client to accept, and keeps it.

It does not fit a receipt the other way round. In Oreoasis's `booking.delivered/1` (OA-V1), the host's book signs the record and asks for the acceptance, and the guest countersigns with a key made for that one relationship. The payload names only the host. The guest holds the bundle, but the guest's key is named nowhere a query could point, so the guest could not sign the binding, and a desk would have issued its decision receipt to the host (IL-V5's open item, `../Indusland 2.0/docs/d93-il-v5.md`).

## Decision

1. **`kash.rule@1.2.0` adds `meta.holder: "countersigner"`** to a `kash-artifact` query. 1.0.0 and 1.1.0 are frozen; every 1.1.0 body is a 1.2.0 body. A reader on predicate `0.2.0-alpha.0` validates against the closed 1.1.0 shape, so it refuses such a rule. It never mis-binds it.
2. **The countersigner is exact.** It is taken only from attest's `verifyCountersignBundle`: acceptances whose own report is `ok` (signature, binding to this request and these bytes, window, the same DID's signature on the subject, no earlier withdrawal), less the requester, distinct. Exactly one must remain, or there is no holder. Predicate keeps the result as `ReceiptView.countersigners`. `view.holder` stays an SD-JWT's `cnf` only, so no existing reader changes what it does.
3. **One reading.** `artifactHolderOf(query, view, artifact)` in predicate is what the desk checks the binding against (`checkPacket`), what the wallet looks for among its keys (`doors.send`), and what a desk issues its decision to (Duedale's `holderOfPacket`, after its re-pin). The `holder_path` and requester branches are unchanged byte for byte.
4. **Validation** refuses `holder` on `dc+sd-jwt`, `holder` beside `holder_path`, and `holder: "countersigner"` without `attestation: countersigned` (`DCQL_MALFORMED`).

## Consequences

### Positive
- A guest presents the booking receipt they accepted, with their own key for that host, and the decision comes back to that key. This is route (a) of Indusland's review door.
- Client Sign-off and every rule that names no `holder` bind exactly as before (tested).
- A forged, misbound, withdrawn or doubled acceptance names no holder, so nothing unsigned can choose the key.

### Negative / accepted trade-offs
- The door learns the guest's key for that host and can recognise the same host relationship if it is shown again (d62(d)3, until the tier-two circuit). The wallet lists the row under `links` before sending.
- Key claims are not followed. After a recovery to a successor key, an old record cannot be presented under the new key.
- A bundle with two countersigners cannot be presented under this mode at all.
- Verifying the bundle a second time (once in `verifyHeldRecord`, once for the acceptances) costs a few signature checks per artifact.

## Alternatives considered
- **Set `view.holder` to the countersigner:** lost, because Duedale's `holderOfPacket` reads `view.holder` first, so every Client Sign-off decision would have gone to the client.
- **A `holder_path` into the acceptance:** lost, because the path points into the signed payload, and an acceptance array's order and validity are not the payload's.
- **Change the default for bundles to the countersigner:** lost, because it would silently re-bind every Client Sign-off record.
- **Extend attest's held-record report instead:** lost, because predicate can read attest's existing verdict, so attest needs no new version.
