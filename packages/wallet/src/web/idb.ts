/**
 * IndexedDB for the web adapter. The root key pair is stored as CryptoKey
 * objects — the browser's structured clone keeps the private key
 * non-extractable — and the vault's blobs as bytes. Nothing here is ever
 * readable as a key: the blobs are ciphertext, and the root cannot be exported.
 */

import type { BlobStore } from "../platform";
import type { WebBackend } from "./index";

const ROOT = "root";
const BLOBS = "blobs";

function request<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function openDb(name: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(name, 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore(ROOT);
      req.result.createObjectStore(BLOBS);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export function indexedDbBackend(dbName = "wallet"): WebBackend {
  let db: Promise<IDBDatabase> | null = null;
  const use = async <T>(storeName: string, mode: IDBTransactionMode, run: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> => {
    db ??= openDb(dbName);
    const tx = (await db).transaction(storeName, mode);
    const done = new Promise<void>((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error);
    });
    const result = await request(run(tx.objectStore(storeName)));
    await done;
    return result;
  };
  const store: BlobStore = {
    put: async (name, bytes) => {
      await use(BLOBS, "readwrite", (s) => s.put(bytes.slice(), name));
    },
    get: async (name) => {
      const v = (await use(BLOBS, "readonly", (s) => s.get(name))) as Uint8Array | undefined;
      return v === undefined ? null : new Uint8Array(v);
    },
    delete: async (name) => {
      await use(BLOBS, "readwrite", (s) => s.delete(name));
    },
    list: async (prefix) => {
      const keys = await use(BLOBS, "readonly", (s) => s.getAllKeys(IDBKeyRange.bound(prefix, `${prefix}￿`)));
      return keys.map(String);
    },
  };
  return {
    getRoot: async () => ((await use(ROOT, "readonly", (s) => s.get(ROOT))) as CryptoKeyPair | undefined) ?? null,
    putRoot: async (pair) => {
      await use(ROOT, "readwrite", (s) => s.put(pair, ROOT));
    },
    store,
  };
}
