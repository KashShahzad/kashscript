/**
 * Browser storage helpers.
 *
 *  • localStorage  → public identity envelope (DID, public key, credential id).
 *  • IndexedDB     → CryptoKey handles (non-extractable Ed25519 private key).
 *
 * No bytes of any private key ever leave WebCrypto: the IndexedDB entry is a
 * `CryptoKey` structured-clone reference, not a raw byte buffer. The browser
 * persists the underlying key material in its own secure store.
 */

import {
  decodeBase58, decodeBase64Url,
  encodeBase58, encodeBase64Url,
  type KashDid,
} from "@kashscript/identity-core";
import { KashSdkError } from "./errors";
import type { KashIdentity, StoredKashIdentity } from "./types";

const LS_KEY  = "kashscript.identity" as const;
const DB_NAME = "kashscript-identity-sdk" as const;
const STORE   = "signers" as const;
const DB_VERSION = 1;

/* ─────────────────────────────────────────────────────────────────
 * localStorage — public identity envelope
 * ───────────────────────────────────────────────────────────────── */

export function readStoredIdentity(): KashIdentity | null {
  if (typeof window === "undefined") return null;
  let raw: string | null;
  try {
    raw = window.localStorage.getItem(LS_KEY);
  } catch (err) {
    throw new KashSdkError("localStorage.getItem failed.", "STORAGE_UNAVAILABLE", err);
  }
  if (!raw) return null;

  let parsed: StoredKashIdentity;
  try {
    parsed = JSON.parse(raw) as StoredKashIdentity;
  } catch (err) {
    throw new KashSdkError("Stored identity is not valid JSON.", "STORAGE_CORRUPT", err);
  }

  if (
    typeof parsed.did !== "string"            ||
    typeof parsed.publicKeyB58 !== "string"   ||
    typeof parsed.credentialIdB64u !== "string"
  ) {
    throw new KashSdkError("Stored identity is missing required fields.", "STORAGE_CORRUPT");
  }

  let publicKey: Uint8Array;
  let credentialId: Uint8Array;
  try {
    publicKey    = decodeBase58(parsed.publicKeyB58);
    credentialId = decodeBase64Url(parsed.credentialIdB64u);
  } catch (err) {
    throw new KashSdkError("Stored identity is corrupted.", "STORAGE_CORRUPT", err);
  }

  return {
    did:          parsed.did as KashDid,
    publicKey,
    credentialId,
    ...(parsed.handle !== undefined ? { handle: parsed.handle } : {}),
  };
}

export function writeStoredIdentity(identity: KashIdentity): void {
  if (typeof window === "undefined") return;
  const envelope: StoredKashIdentity = {
    did:              identity.did,
    publicKeyB58:     encodeBase58(identity.publicKey),
    credentialIdB64u: encodeBase64Url(identity.credentialId),
    updatedAt:        new Date().toISOString(),
    ...(identity.handle !== undefined ? { handle: identity.handle } : {}),
  };
  try {
    window.localStorage.setItem(LS_KEY, JSON.stringify(envelope));
  } catch (err) {
    throw new KashSdkError("localStorage.setItem failed.", "STORAGE_UNAVAILABLE", err);
  }
}

export function clearStoredIdentity(): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.removeItem(LS_KEY);
  } catch (err) {
    throw new KashSdkError("localStorage.removeItem failed.", "STORAGE_UNAVAILABLE", err);
  }
}

/* ─────────────────────────────────────────────────────────────────
 * IndexedDB — opaque CryptoKey handle storage
 * ───────────────────────────────────────────────────────────────── */

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined") {
      reject(new KashSdkError("indexedDB is not available.", "STORAGE_UNAVAILABLE"));
      return;
    }
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (): void => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE);
      }
    };
    req.onsuccess = (): void => resolve(req.result);
    req.onerror   = (): void => {
      reject(new KashSdkError("Failed to open IndexedDB.", "STORAGE_UNAVAILABLE", req.error));
    };
  });
}

function txComplete(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = (): void => resolve();
    tx.onerror    = (): void => reject(tx.error);
    tx.onabort    = (): void => reject(tx.error);
  });
}

export async function storeSignerKey(did: KashDid, key: CryptoKey): Promise<void> {
  const db = await openDb();
  try {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(key, did);
    await txComplete(tx);
  } finally {
    db.close();
  }
}

export async function loadSignerKey(did: KashDid): Promise<CryptoKey | null> {
  const db = await openDb();
  try {
    const tx = db.transaction(STORE, "readonly");
    const req = tx.objectStore(STORE).get(did);
    const value = await new Promise<unknown>((resolve, reject) => {
      req.onsuccess = (): void => resolve(req.result);
      req.onerror   = (): void => reject(req.error);
    });
    await txComplete(tx);
    if (value === undefined || value === null) return null;
    // Sanity: structured-clone returns the stored CryptoKey reference.
    return value as CryptoKey;
  } finally {
    db.close();
  }
}

export async function removeSignerKey(did: KashDid): Promise<void> {
  const db = await openDb();
  try {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).delete(did);
    await txComplete(tx);
  } finally {
    db.close();
  }
}
