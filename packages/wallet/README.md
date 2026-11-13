# @kashscript/wallet

The wallet component: records held on the holder's own device, with **keys first and no account**. It receives records, holds them sealed and deletes them at expiry for real, answers a request with one yes and never the data, keeps the holder's own log, checks anyone's receipt offline, and exports everything as one documented file. Apache-2.0: holding, presenting and checking are free, and a stranger can build a competing wallet from [the spec](../../specs/wallet.md) and [the holder contract](../../specs/holder-contract.md).

> **`0.1.0-alpha.0` and `0.1.0-alpha.1` are published, and both the `latest` and `alpha` tags point at `alpha.1`** `[v 10-09, npm view]` (`latest` was moved off `alpha.0` that day). `bun add @kashscript/wallet` installs it; it is still a prerelease. The native half (Swift, Kotlin) compiles in an app's development build, not here. Recovery with helpers is an interface only until PL-2, and it says so. Nothing has run with a person.

```ts
import { createExpoWallet } from "@kashscript/wallet/expo";     // a phone: the secure chip
import { createWebWallet } from "@kashscript/wallet/web";       // a browser: weaker, and labelled so
import { createHeadlessWallet } from "@kashscript/wallet/headless"; // practice runs only

const wallet = await createExpoWallet({ pinnedPublishers: [PUBLISHER_DID] });
await wallet.unlock();                                   // one face, fingerprint or screen-lock prompt

await wallet.proof.set(place, "on", "The café");          // asked once per place; never pre-ticked
const view = await wallet.receive.open(scannedOffer);    // built on OpenID4VCI 1.0, pre-authorized
await wallet.receive.accept(view);

const ask = await wallet.present.open(scannedRequest);   // built on OpenID4VP 1.0; the ask checked first
await wallet.present.yes(ask);                           // or: wallet.present.no(ask) — sends nothing
const file = await wallet.exportAll({ passphrase });     // keys only when asked, encrypted
wallet.lock();                                           // when the app goes to the background
```

**Conformance: none claimed.** It is *built on* OpenID4VCI 1.0 and OpenID4VP 1.0 and is **not conformant**: the OpenID Foundation's suites were run on 2026-10-10 and no HAIP test passed. It speaks the anonymous, pre-authorized profile; HAIP asks for the authorization-code flow and wallet attestation, which the holder contract refuses. Results and causes: `docs/conformance/2026-10-10` (the run's logs, kept with the private archive).

**What it will not do.** The hardware root never signs a record — it has no sign method, and the chip's key types can't. A key never leaves the device in the clear. The switch never leaves the device. No push token, install id or account id travels with anything, and a guard refuses any request carrying one relationship's identifier to another. It holds no money, balance or card; a thank-you is a single note, never summed. No default word names the ecosystem, a member, or a word a person must learn.

**The Expo adapter** autolinks the `KashWalletRoot` native module (`ios/`, `android/`) and needs a development build. React Native has no WebCrypto: install one (react-native-quick-crypto lists every algorithm used) before creating the wallet — `checkRuntime()` names anything missing. The root needs a screen lock, and on Android, version 12 or later.

**The headless mode** runs the wallet's scenarios for the simulation: `bun run headless`.
