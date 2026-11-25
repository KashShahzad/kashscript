# @kashscript/kash

> **`kash` — the station kit.** It makes a station's own keys, writes a cohort record as a file, countersigns it as the station, checks any record offline, signs a trust list with the publisher key, and keeps the trust log. Local files only: **no server, no upload, and no delivery into a wallet.** Two commands go online, to public witnesses only, and say so first: `kash log witness` and `kash log upgrade`.

```bash
npx @kashscript/kash --help      # Node 20+, or Bun 1+
```

`kash verify` runs the verifier from `@kashscript/attest`, and `kash log` its trust log; attest is installed alongside it, at the version published with this one.

## What it does

```
kash station init [--name station]    Make a key in your own keystore; print its DID.
kash issue cohort …                   The teacher's organisation writes a pending cohort record, and a carried link.
kash countersign <link>               The station countersigns it, with its own key → the finished record.
kash verify <file>                    Check a record, bundle, trust list or status list. Offline.
kash trust sign <file>                Sign a trust list or status list with the publisher key.
kash log init|add|checkpoint|proof    Keep the trust log: a folder any host serves and mirrors. Offline.
kash log witness|upgrade              Send a head's hash to OpenTimestamps or an RFC 3161 authority. Online.
kash pack build|list                  Check a set-up pack folder against the open-rule validator and floor. Offline.
kash pack install <dir> --host <url>  Install a pack on a clean practice organisation and complete its first approval. Online.
kash status                           The keystore, and whether each key file is still private to you.
kash doctor | add | rollback          The project-integration commands (unchanged, apart from losing their login).
```

**Paper is the floor.** A record is a file. `kash verify` checks it with no key, no account and no service, so a stranger can too. The Chakor wallet receives records only over OpenID4VCI, from an issuer's own HTTPS origin — so a file or link from `kash` cannot put a record into a wallet, and `kash` does not try. Delivery is an online issuer's job.

### Station zero, step by step

*(Every name, DID and file below is a simulation.)* Two organisations sign, each with its own key, each in its own step. One organisation cannot countersign itself (d26).

```bash
# Each organisation makes its own key, once, on its own machine.
kash station init --name teacher        # the teacher's organisation
kash station init --name station        # the station — the DID its charter will name

# The teacher's organisation writes the record, with its key. It carries one of the two signatures.
#   --holder   the relationship key the learner's wallet made for this issuer
#   --station  the station's DID (public; its key is not needed here)
kash issue cohort \
  --holder did:kash:… --station did:kash:… \
  --syllabus-id did:kash:<teacher>/syllabus/web-foundations \
  --syllabus-version 1.0 --syllabus-file ./syllabus.md \
  --finished 2026-09-25T12:00:00.000Z --expires 2029-09-25T12:00:00.000Z
#  → cohort-record.pending.json  +  a carried link on the screen

kash verify cohort-record.pending.json  # exit 1: MISSING_COUNTERSIGNATURE — one signature is not proof

# The station gets the link and the file, reads what it is signing, and says yes or no.
kash countersign <link> --record cohort-record.pending.json     # → cohort-record.json
kash verify cohort-record.json          # exit 0
```

- `--expires` has no default: how long a record lasts is yours to set.
- `kash countersign` shows the holder's key, the syllabus (id, version, SHA-256), the dates and the teacher's organisation, and asks. **A no signs nothing and writes nothing** (d49). `--yes` is for a script whose person has already decided.
- It refuses to sign if the record names a different station than the key it was given, and it checks the finished record before writing it.
- The syllabus is named by where it is published, its version, and the SHA-256 of its exact bytes — `kash` hashes the file you give it.

### `kash verify`

Runs attest's own verifier, `attest verify`, and returns its exit code: **0** PASS · **1** verification FAILED · **2** usage or IO error (also when the file cannot be read or recognised) · **3** INTEGRITY ONLY (attest's, passed through: a DSSE audit bundle or an Every-Rupee report checked with no key is consistent with itself and says nothing about who signed it — never a cohort record, whose keys are self-certifying). It never touches the network: there is no `--check-status`, and every key comes out of the file's own `did:kash` identifiers. The report ends with who signed, what was checked and what it does not prove, then `RESULT:`.

### `kash trust sign`

```bash
kash station init --name publisher                     # once, where only you hold it
kash trust sign list.json > trust-list.signed.json     # stdout is the signed file and nothing else
kash verify trust-list.signed.json --trust-publisher did:kash:<publisher>
```

Takes an unsigned `kashscript-trust-list/1` or `kashscript-status-list/1` payload and signs it in the wallet's own format. It fills in the publisher from the key, refuses a list that names someone else, checks its own result and prints nothing if it would not verify. The default key is `publisher` — **never the station's key**. A wallet trusts a list only if its app pins that publisher's DID out of band. Publishing the file is yours to do.

### `kash log`

```bash
kash log init ./log --name scheme                      # log.json names the publisher key; the id is <did>/log/scheme
kash log add ./log trust-list.signed.json              # its version, and a key event for every key it names
kash log add ./log trust-list-v2.signed.json --previous trust-list.signed.json
kash log add ./log attestation.json                    # {v:1, kind:"attestation", issuer, salted, claimedAtUnix}
kash log checkpoint ./log                              # the head, signed with the publisher key
kash log witness ./log --tsa --tsa-root digicert.pem   # online: OpenTimestamps, and DigiCert's RFC 3161 authority beside it
kash log upgrade ./log                                 # online, hours later: the Bitcoin attestation
kash log proof ./log 3 > proof-3.json                  # one entry's proof; anyone checks it with attest verify
```

The log holds issuers and lists, and attestations by salted hash. It never holds a person, a presentation or a record's content, and `add` refuses all of them, checking the whole batch before it writes any of it. A signed trust list goes in as its version plus its key events (added, rotated, revoked); a second version needs `--previous`, the version the log already holds. A claim from before the log began must be marked `backfilled`: its time will be the witness's, never the claim. A checkpoint's time is the log's own word until a witness stamps it. `--tsa-root <pem>` keeps an RFC 3161 token only if openssl verifies it against that root. The folder is the log: serve it from any static host. Anyone checks it, and compares a mirror, with `attest log verify <dir> --mirror <copy>`. The specification is [`specs/trust-log.md`](../../specs/trust-log.md).

## What a record does not prove

A cohort record says three things: a cohort was finished, under a syllabus at a named version, and the teacher's organisation and the station each countersigned it with their own keys. It does **not** prove:

- **How well anyone learned.** It carries no grade, score or rank, and proves no skill level.
- **Who the holder is.** It names a key their wallet made for this issuer alone, and a key is not a person.
- **That the keys belong to those organisations.** A charter, or a trust list the verifier pinned, says that — not the file.
- **Who paid, or whether a seat was sponsored.** That is never in the record.
- **That a capstone exists or that a client accepted it.** That is its own record.
- **Attendance, effort or deviations.**
- **That it has not been withdrawn.** Absence of a withdrawal cannot be proven offline.
- **When it was signed.** Signing times are the signers' own claims.

## What it does not protect

- **Showing a record links its holder** (d62(d)3). Every verifier shown it sees the same bytes and the same holder key, so two verifiers can tell it is one person, and the issuer knows whose key it is. Show it only where being recognised as its holder is fine.
- **The key file is plain JSON.** Nothing encrypts it; the only guard is that it is readable by you alone. `kash station init` sets that and then *reads it back* — it says "confirmed" only when the check passed, and says so loudly when it did not. On Windows it uses `icacls` (inheritance removed, your account only — which also removes SYSTEM and Administrators from the file); elsewhere, mode `0600` in a `0700` folder. Anyone who can run code as you can read the key.
- **There is no recovery.** A lost key file is a new key and a new DID. Back it up offline, never to a server (d47).
- **Nothing here checks that a DID belongs to an organisation.** A key is only a key until a charter says whose.

## Where things are

- **Keystore:** `--keystore <dir>`, else `$KASH_KEYSTORE`, else `~/.kash/keys`. One `<name>.key.json` per key. `--key <name|path>` picks one; `issue` defaults to `teacher`, `countersign` to `station`, `trust sign` and `log` to `publisher`.
- **Nothing leaves the machine unless you run an online command.** `kash log witness` sends a checkpoint's 32-byte hash to public witnesses, `kash log upgrade` asks a calendar for its own commitment, and `kash pack install` talks only to the practice `--host` you pass (refusing any host not running practice mode); each says `ONLINE` first. No other command opens a socket, and the tests run the bundled binary with every route to the network switched off.

## Older commands

`kash add <product>`, `kash doctor` and `kash rollback` integrate products into a project. They have no login or licence check — there is none. `kash add` installs `identity`, `terms`, `muffler` or `whiffin`, as a dry run until you pass `--apply`.

`kash add terms` is what `kash add trade` became: trade-core and trade-sdk are retired (ecosystem d59), and the agreement kernel lives on as [`@kashscript/terms`](../terms) (Apache-2.0), which moves nothing and holds no balance. `kash add whiffin` scaffolds the mandate protocol, which never moves money. `kash add neuron` and `kash add hudhud` are gone: both are closed code inside the Oreoasis engine, published nowhere (ecosystem d87, d90). Asking for `trade`, `neuron` or `hudhud` says so and points to the replacement.

`kash login`, `logout`, `browse`, `trade`, `neuron` and `sync` are gone as commands, and so is the kash-registry client.

## License

Apache-2.0. See [LICENSE](./LICENSE).
