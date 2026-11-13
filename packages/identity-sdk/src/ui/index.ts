/**
 * @kashscript/identity-sdk/ui — Tailwind-styled React components.
 *
 * Opt-in: only imported when consumers explicitly bring in the subpath. The
 * headless logic in `@kashscript/identity-sdk` remains UI-free.
 */

export * from "./KashConnect";
export * from "./IdentityWidget";
export * from "./SignTransactionModal";
export * from "./ShadowFrame";
export * from "./SignInGate";
export { sanitiseDisplayText, sanitiseDisplayValue, hasSuspiciousChars } from "./sanitise";
