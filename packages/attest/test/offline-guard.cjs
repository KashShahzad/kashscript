// Loaded with `node --require ./test/offline-guard.cjs …`. Every way a Node
// process can reach the network throws, so a command that still passes under
// it provably verified from the file alone.
"use strict";

function refuse(what) {
  return function () {
    throw new Error(`offline-guard: ${what} is disabled — this check must not touch the network`);
  };
}

globalThis.fetch = refuse("fetch");
for (const [mod, fns] of [
  ["net", ["connect", "createConnection"]],
  ["tls", ["connect"]],
  ["dns", ["lookup", "resolve", "resolve4", "resolve6"]],
  ["http", ["request", "get"]],
  ["https", ["request", "get"]],
  ["http2", ["connect"]],
  ["dgram", ["createSocket"]],
]) {
  const m = require(mod);
  for (const fn of fns) m[fn] = refuse(`${mod}.${fn}`);
}
const dnsPromises = require("dns").promises;
for (const fn of ["lookup", "resolve", "resolve4", "resolve6"]) dnsPromises[fn] = refuse(`dns.promises.${fn}`);
