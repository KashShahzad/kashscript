// MufflerClient — writes a repo's records to its PDS through a transport.
//
// Transport-agnostic: it speaks to an XrpcTransport, not a hardwired atproto
// SDK. The atproto adapter (AtpAgent -> XrpcTransport) is the deployment wiring;
// keeping the client behind this seam lets the rkey/refine logic be unit-tested
// without a live PDS and lets consumers swap transports. When a Refiner is
// supplied, every write to a handled collection is refined (validated +
// canonical) before it leaves the process.
//
// Ported from the @indus/muffler seed (M3, ADR-0016). The venture's typed
// put*() convenience methods (putProfile/putExperience/…) stay venture-side;
// the generic client exposes a single `put(collection, rkey, record)`.

import type { Refiner } from "./refine";

export interface BlobRef {
  cid: string;
  mimeType: string;
  size?: number;
}

export interface PutRecordInput {
  collection: string;
  rkey: string;
  record: unknown;
}

export interface PutRecordResult {
  uri: string;
  cid: string;
}

export interface ListRecordsResult {
  records: Array<{ uri: string; cid: string; value: unknown }>;
  cursor?: string;
}

export interface XrpcTransport {
  putRecord(input: PutRecordInput): Promise<PutRecordResult>;
  deleteRecord(input: { collection: string; rkey: string }): Promise<void>;
  uploadBlob(bytes: Uint8Array, mimeType: string): Promise<BlobRef>;
  listRecords(collection: string, opts?: { limit?: number; cursor?: string }): Promise<ListRecordsResult>;
}

const BASE32_SORTABLE = "234567abcdefghijklmnopqrstuvwxyz";
let lastTidMicros = 0;

// Sortable record key. Not a spec-perfect atproto TID, but monotonic and
// collision-free within a process, which is all an rkey needs here.
export function tid(): string {
  let micros = Date.now() * 1000;
  if (micros <= lastTidMicros) micros = lastTidMicros + 1;
  lastTidMicros = micros;
  let n = micros;
  let out = "";
  for (let i = 0; i < 13; i++) {
    out = BASE32_SORTABLE[n % 32] + out;
    n = Math.floor(n / 32);
  }
  return out;
}

export class MufflerClient {
  constructor(
    private readonly transport: XrpcTransport,
    readonly did: string,
    private readonly refiner?: Refiner,
  ) {}

  /** Write a record. When a Refiner handles the collection, the record is
   *  validated + canonicalized before the transport sees it; otherwise it is
   *  written through as-is. */
  async put(collection: string, rkey: string, record: unknown): Promise<PutRecordResult> {
    const value =
      this.refiner !== undefined && this.refiner.handles(collection)
        ? (await this.refiner.refine(collection, record)).value
        : record;
    return this.transport.putRecord({ collection, rkey, record: value });
  }

  deleteRecord(collection: string, rkey: string): Promise<void> {
    return this.transport.deleteRecord({ collection, rkey });
  }

  uploadBlob(bytes: Uint8Array, mimeType: string): Promise<BlobRef> {
    return this.transport.uploadBlob(bytes, mimeType);
  }

  listRecords(collection: string, opts?: { limit?: number; cursor?: string }): Promise<ListRecordsResult> {
    return this.transport.listRecords(collection, opts);
  }
}
