/** The three types PL-3 registered first (see `../dst.ts`). */
export const PREDICATE_VCT = "https://kashscript.com/vct/predicate/1" as const;
export const THANK_YOU_VCT = "https://kashscript.com/vct/thank-you/1" as const;
export const SESSION_EVENT_DST = "application/vnd.indorania.session-event+json" as const;
/** The session anchor's leaf (GP-6, registered first): SHA-256(0x00 ‖ this tag ‖ treeSize, 8 bytes ‖ head). */
export const SESSION_HEAD_LEAF_DST = "kash-session-head-v1\n" as const;
