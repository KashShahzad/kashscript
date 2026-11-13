/**
 * @kashscript/wallet/headless — the wallet for the simulation (PL-5) and tests.
 * **Practice only, never for a person.** A headless wallet, the practice hosts
 * a run needs, and the wallet's scenarios with their constitutional checks.
 */

export { createHeadlessWallet, type HeadlessOptions, type HeadlessWallet } from "./wallet";
export { PracticeNetwork, type Handler } from "./practice/network";
export { PracticeIssuer, PRACTICE_RECORD_DST, type PracticeConfig, type PracticeSdJwtConfig } from "./practice/issuer";
export { PracticeVerifier, type Received } from "./practice/verifier";
export { PracticeDesk, type DeskReceived } from "./practice/desk";
export { PracticeEstablishment } from "./practice/establishment";
export { PracticePublisher } from "./practice/publisher";
export { runWalletScenarios, WALLET_SCENARIOS, BANNED_WORDS, PRACTICE_T0, type ScenarioName, type ScenarioResult, type AssertionResult } from "./scenarios";
export { formatReport } from "./report";
