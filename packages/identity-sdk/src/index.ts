/**
 * @kashscript/identity-sdk — main surface.
 *
 * React entry point for the Kash Identity Foundry. Bridges WebAuthn Passkeys
 * to the did:kash crypto layer (`@kashscript/identity-core`) and exposes
 * headless React hooks for app integration.
 *
 * Browser-only: every entry point assumes `window`, `navigator.credentials`,
 * `crypto.subtle`, `localStorage`, and `indexedDB` are available. The Provider
 * is marked `"use client"` so it can sit at the top of a Next.js App-Router
 * tree without polluting server-side rendering.
 */

export * from "./errors";
export * from "./types";
export * from "./webauthn";
export * from "./storage";
export * from "./storage-adapter";
export * from "./recovery";
export * from "./rotation";
export * from "./revocation";
export * from "./provider";
export * from "./hooks";

export const IDENTITY_SDK_VERSION = "0.1.4" as const;
