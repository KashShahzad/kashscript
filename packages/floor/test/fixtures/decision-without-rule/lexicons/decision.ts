declare const S: { object(props: Record<string, unknown>, required?: string[]): unknown; string(): unknown };

export const DECISION_BODY = S.object({ outcome: S.string(), rule: S.object({ id: S.string() }, ["id"]) }, ["outcome", "rule"]);
