/**
 * The practice network: an in-process router standing in for the internet.
 * Every practice host lives under `.practice.invalid` — a name that can never
 * resolve (RFC 2606) — so even a slip could not reach a real server.
 */

import type { HttpRequest, HttpResponse, Transport } from "../../platform";

export type Handler = (req: HttpRequest) => Promise<HttpResponse>;

export class PracticeNetwork {
  private readonly hosts = new Map<string, Handler>();

  mount(origin: string, handler: Handler): void {
    if (!origin.endsWith(".practice.invalid")) throw new Error("practice hosts live under .practice.invalid");
    this.hosts.set(origin, handler);
  }

  readonly transport: Transport = async (req) => {
    const handler = this.hosts.get(new URL(req.url).origin);
    if (handler === undefined) return { status: 404, text: "" };
    return handler(req);
  };
}

export const json = (status: number, body: unknown): HttpResponse => ({ status, text: JSON.stringify(body) });

export function formOf(req: HttpRequest): URLSearchParams {
  return new URLSearchParams(req.body ?? "");
}

export function jsonOf(req: HttpRequest): Record<string, unknown> | null {
  try {
    const v = JSON.parse(req.body ?? "") as unknown;
    return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}
