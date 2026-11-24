/**
 * @kashscript/floor — the runtime. Server code imports `suppress` from here; it loads no compiler and touches no file.
 * The scanner is `@kashscript/floor/check`, and the command line is `kash-floor`.
 */

export { FLOOR_K, suppress, suppressSeries } from "./suppress.js";
export type { FloorCount, FloorTotal, FloorSeries, FloorList, SeriesOptions } from "./suppress.js";
export { RULES, CITE } from "./rules.js";
export type { RuleId, RuleInfo, CiteKey } from "./rules.js";
