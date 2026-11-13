/** An in-memory blob store — for the headless mode and tests. Nothing survives the process. */

import type { BlobStore } from "../platform";

const NAME = /^[a-z0-9.]+$/;

export class MemoryStore implements BlobStore {
  private readonly blobs = new Map<string, Uint8Array>();

  async put(name: string, bytes: Uint8Array): Promise<void> {
    if (!NAME.test(name)) throw new Error(`bad store name ${name}`);
    this.blobs.set(name, bytes.slice());
  }

  async get(name: string): Promise<Uint8Array | null> {
    return this.blobs.get(name)?.slice() ?? null;
  }

  async delete(name: string): Promise<void> {
    const b = this.blobs.get(name);
    if (b) b.fill(0);
    this.blobs.delete(name);
  }

  async list(prefix: string): Promise<readonly string[]> {
    return [...this.blobs.keys()].filter((n) => n.startsWith(prefix));
  }

  /** Every name and its bytes, for assertions: a decline must change none of them. */
  snapshot(): ReadonlyMap<string, Uint8Array> {
    return new Map([...this.blobs.entries()].map(([k, v]) => [k, v.slice()]));
  }
}
