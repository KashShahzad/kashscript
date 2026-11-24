declare const S: { object(props: Record<string, unknown>, required?: string[]): unknown; string(): unknown };

export const KASH_EDU_TRANSCRIPT_BODY_SCHEMA = S.object({ studentDid: S.string(), courseCode: S.string(), grade: S.string() }, ["studentDid"]);
