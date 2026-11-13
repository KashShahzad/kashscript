/**
 * GZIP for status lists. The web-standard streams where the runtime has them
 * (browsers, Node ≥ 18); an injected decompressor where the runtime lacks them
 * (React Native via the wallet's Expo adapter); `node:zlib` otherwise (Bun 1.2
 * has no `DecompressionStream`). Both produce and accept RFC 1952 gzip.
 */

export type InflateFunction = (bytes: Uint8Array) => Uint8Array | Promise<Uint8Array>;

let injectedInflate: InflateFunction | null = null;

/**
 * Supply an inflate implementation for environments without DecompressionStream
 * or node:zlib (e.g. React Native / Hermes).
 */
export function setInflate(fn: InflateFunction | null): void {
  injectedInflate = fn;
}

export function getInflate(): InflateFunction | null {
  return injectedInflate;
}

export type ZlibProvider = () => Promise<{
  gzipSync(bytes: Uint8Array): Uint8Array | Buffer;
  gunzipSync(bytes: Uint8Array): Uint8Array | Buffer;
}>;

let zlibProvider: ZlibProvider = () => import("node:zlib");

/** Hook for tests to simulate an environment lacking node:zlib. */
export function setZlibProvider(provider: ZlibProvider): void {
  zlibProvider = provider;
}

type StreamCtor = new (format: "gzip") => TransformStream<Uint8Array, Uint8Array>;

function streamCtor(name: "CompressionStream" | "DecompressionStream"): StreamCtor | null {
  const ctor = (globalThis as Record<string, unknown>)[name];
  return typeof ctor === "function" ? (ctor as StreamCtor) : null;
}

async function throughStream(bytes: Uint8Array, stream: TransformStream<Uint8Array, Uint8Array>): Promise<Uint8Array> {
  const piped = new Blob([bytes as unknown as BlobPart]).stream().pipeThrough(stream);
  return new Uint8Array(await new Response(piped).arrayBuffer());
}

export async function gzip(bytes: Uint8Array): Promise<Uint8Array> {
  const Ctor = streamCtor("CompressionStream");
  if (Ctor !== null) return throughStream(bytes, new Ctor("gzip"));
  const zlib = await zlibProvider();
  return new Uint8Array(zlib.gzipSync(bytes));
}

export async function gunzip(bytes: Uint8Array, inflate?: InflateFunction | undefined): Promise<Uint8Array> {
  const custom = inflate ?? injectedInflate;
  if (custom !== null) return custom(bytes);
  const Ctor = streamCtor("DecompressionStream");
  if (Ctor !== null) return throughStream(bytes, new Ctor("gzip"));
  const zlib = await zlibProvider();
  return new Uint8Array(zlib.gunzipSync(bytes));
}
