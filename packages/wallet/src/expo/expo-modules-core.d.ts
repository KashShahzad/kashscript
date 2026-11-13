/**
 * The one function this package uses from `expo-modules-core`, declared here
 * so the package builds without pulling React Native into the monorepo. An
 * Expo app always has the real module; its signature matches this one.
 */
declare module "expo-modules-core" {
  export function requireOptionalNativeModule<ModuleType = unknown>(moduleName: string): ModuleType | null;
}
