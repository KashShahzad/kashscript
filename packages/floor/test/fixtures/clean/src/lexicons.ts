declare const S: { object(props: Record<string, unknown>, required?: string[]): unknown; string(): unknown; number(): unknown };

/** A transcript entry about a student: what the institution awards, and no score of the student. */
export const TRANSCRIPT_BODY = S.object({ studentDid: S.string(), courseCode: S.string(), credits: S.number() }, ["studentDid", "courseCode"]);
