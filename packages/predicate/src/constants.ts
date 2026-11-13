/** The registered types a door uses (attest's registry, `src/dst.ts`). A test keeps them in step. */
export const RULE_PAYLOAD_TYPE = "application/vnd.kash.rule+json" as const;
export const DECISION_VCT = "https://kashscript.com/vct/decision/1" as const;
export const OWN_WORD_VCT = "https://kashscript.com/vct/own-word/1" as const;

/** Credential formats a rule may query in this version (OpenID4VP 1.0 Appendix B, plus the holder contract's profile). */
export const SD_JWT_FORMAT = "dc+sd-jwt" as const;
export const KASH_ARTIFACT_FORMAT = "kash-artifact" as const;
export const READABLE_FORMATS: readonly string[] = [SD_JWT_FORMAT, KASH_ARTIFACT_FORMAT];

/** The binding a `kash-artifact` presentation carries — the counterpart of SD-JWT's KB-JWT. */
export const ARTIFACT_KB_TYP = "kash-artifact-kb+jwt" as const;

/** `trusted_authorities` types of ours, in OpenID4VP's extension point (§6.1.1). */
export const TA_ISSUER = "kash_issuer" as const;
export const TA_TRUST_LIST = "kash_trust_list" as const;

/** Names a condition may not declare: the evaluator binds them. */
export const RESERVED_NAMES: readonly string[] = ["receipts", "asOf", "item", "issuer"];

/** d43: a rule renews within a year of publication and ends within three. */
export const MAX_RENEW_DAYS = 366;
export const MAX_LIFE_DAYS = 1096;

export const DAY = 86_400;
