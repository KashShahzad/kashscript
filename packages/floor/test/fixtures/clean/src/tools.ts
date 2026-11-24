function def<T>(t: T): T {
  return t;
}

export const TOOLS = {
  find_listings: def({ name: "find_listings", kind: "prepare" }),
  "host.read_queue": def({ name: "host.read_queue", kind: "prepare" }),
} as const;
