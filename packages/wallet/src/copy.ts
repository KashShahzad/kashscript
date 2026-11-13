/**
 * The words the component gives an app by default — plain English, every one
 * overridable. d44's test binds them: a person must be able to use a wallet
 * built on this without learning the name of the ecosystem, its members, its
 * programs, or words like "proof economy" and "standing". The wallet list of
 * the design language (d51) adds the technical words a person never needs.
 * `test/copy.test.ts` fails on any of them, here and in every error message.
 *
 * Placeholders are `{name}`; fill them with {@link fill}. Every state has
 * words — nothing here relies on a glyph or a colour to be understood.
 */

export interface Copy {
  readonly unlockPrompt: string;
  readonly rootHardware: string;
  readonly rootBrowser: string;
  readonly rootPractice: string;
  readonly rootNeedsScreenLock: string;
  readonly rootNeedsNewerSystem: string;
  readonly rootNoSecureChip: string;
  readonly switchQuestion: string;
  readonly switchYes: string;
  readonly switchNo: string;
  readonly switchNote: string;
  readonly askWhy: string;
  readonly askGoodFor: string;
  readonly askDeclineCosts: string;
  readonly askInLibrary: string;
  readonly askNotInLibrary: string;
  readonly askMissing: string;
  readonly unlistedKeepQuestion: string;
  readonly checkSignedByBoth: string;
  readonly checkOneSignature: string;
  readonly checkSigned: string;
  readonly checkDeviceOnly: string;
  readonly checkDoesntMatch: string;
  readonly checkExpired: string;
  readonly checkPractice: string;
  readonly checkListed: string;
  readonly checkUnlisted: string;
  readonly notProvenCountersigned: string;
  readonly notProvenSigned: string;
  readonly notProvenDeviceOnly: string;
  readonly notProvenOneSignature: string;
  readonly thankYouNote: string;
  readonly thankYouUseWith: string;
  readonly signPrompt: string;
  readonly recoveryChooseHelpers: string;
  readonly recoveryReady: string;
  readonly recoveryUncovered: string;
  readonly recoveryNeedsCopy: string;
  readonly recoveryHelperQuestion: string;
  readonly recoveryWaiting: string;
  readonly recoveryDone: string;
  readonly recoveryShowPlace: string;
  readonly recoveryNotPeople: string;
  readonly backupExplain: string;
  readonly backupChipKeys: string;
  readonly exportWarn: string;
  readonly importNoKeys: string;
  readonly practiceHeading: string;
}

export const DEFAULT_COPY: Copy = {
  unlockPrompt: "Unlock your records",
  rootHardware: "Your keys are kept in this phone's secure chip. Only your face, fingerprint or screen lock opens them.",
  rootBrowser: "Your keys are kept by this browser. A phone's secure chip keeps them better.",
  rootPractice: "Practice keys, kept in memory. Never use them for real records.",
  rootNeedsScreenLock: "Set a screen lock on this phone first. Your keys need it.",
  rootNeedsNewerSystem: "This phone's system is too old to keep your keys in its secure chip. You can still take part by text message or with a file.",
  rootNoSecureChip: "This phone has no secure chip to keep your keys in. You can still take part by text message or with a file.",
  switchQuestion: "Keep a record of what you do with {name}?",
  switchYes: "Keep a record",
  switchNo: "No record",
  switchNote: "You can change this any time. Saying no changes nothing else about your visit.",
  askWhy: "Why they ask: {why}",
  askGoodFor: "What a yes gets you: {goodFor}",
  askDeclineCosts: "Saying no costs only this: {goodFor}",
  askInLibrary: "This request matches the public list of requests.",
  askNotInLibrary: "This request isn't in your copy of the public list of requests.",
  askMissing: "You don't hold what this request needs.",
  unlistedKeepQuestion: "This came from {name}, who isn't on your list of known senders. Keep it anyway?",
  checkSignedByBoth: "Signed by both sides.",
  checkOneSignature: "One signature so far. It isn't proof until both sides sign.",
  checkSigned: "Signed by {name}. One signature is a claim by its signer.",
  checkDeviceOnly: "Signed only by the holder's own device.",
  checkDoesntMatch: "Doesn't match. It was changed, or the signature is wrong.",
  checkExpired: "Expired.",
  checkPractice: "Practice. Not a real-world fact.",
  checkListed: "From {name}, who is on your list of known senders.",
  checkUnlisted: "From someone who isn't on your list of known senders.",
  notProvenCountersigned: "This shows two independent sides signed it at a time. It doesn't show that what it says is true, or that nothing was left out.",
  notProvenSigned: "This shows who signed it. It doesn't show that anyone else agrees.",
  notProvenDeviceOnly: "This shows a device signed it. No one else vouches for it.",
  notProvenOneSignature: "Only one side has signed. It isn't proof of anything yet.",
  thankYouNote: "{value}. From {name}.",
  thankYouUseWith: "Use it with {name} by {date}.",
  signPrompt: "Sign with your key for this place",
  recoveryChooseHelpers: "If you lose this phone, people you trust can help you get your keys back. Choose at least two, who don't share a home or a phone with you. More than half of them must agree.",
  recoveryReady: "{need} of your {count} helpers can bring your keys back on a new phone.",
  recoveryUncovered: "{n} of your places aren't covered yet. Meet a helper to add more.",
  recoveryNeedsCopy: "Keep a copy of your records somewhere other than this phone. Helpers bring back your keys, not your records.",
  recoveryHelperQuestion: "{name} says they lost their phone. Only say yes if you've spoken to them yourself and their screen shows {code}.",
  recoveryWaiting: "Waiting for {n} more helper.",
  recoveryDone: "Your keys are back. Each place sees your new key only if you show it.",
  recoveryShowPlace: "Show {name} that this is still you, from your old phone?",
  recoveryNotPeople: "Your phone can't tell whether two helpers are the same person. Choose different people.",
  backupExplain: "This saves your keys in the file, locked with a passphrase you choose. Anyone with the file and the passphrase can use your keys.",
  backupChipKeys: "{n} of your keys stay in this phone's secure chip and can't go in any file. If you lose the phone, your helpers bring them back.",
  exportWarn: "This file holds all your records and the separate name you use with each place. Keep it to yourself.",
  importNoKeys: "Your records are back. To use them with the places that gave them, you'll need your keys too.",
  practiceHeading: "practice run — not a real-world fact",
};

export function copyWith(overrides: Partial<Copy> = {}): Copy {
  return { ...DEFAULT_COPY, ...overrides };
}

/** Fill `{name}` placeholders. A missing value leaves the placeholder visible rather than guessing. */
export function fill(template: string, values: Readonly<Record<string, string>>): string {
  return template.replace(/\{(\w+)\}/g, (whole, key: string) => (key in values ? values[key]! : whole));
}
