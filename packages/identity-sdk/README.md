# @kashscript/identity-sdk

> **React + WebAuthn SDK for `did:kash`.** Passkey-backed login, hooks, and opinionated UI components for the Kash Identity Foundry.

```bash
bun add @kashscript/identity-sdk @kashscript/identity-core react react-dom
```

`react` and `react-dom` are peer deps — the SDK works with React 18 or 19,
in Next.js (App Router or Pages), Remix, Vite, plain CRA, and React Native
Web. The headless logic in the root export is UI-free; opt into the
Tailwind-styled components via the `/ui` subpath.

---

## Quickstart — a sign-in flow in 3 components

```tsx
// 1. Wrap the app once
import { KashAuthProvider } from "@kashscript/identity-sdk/provider";

export default function App({ children }: { children: React.ReactNode }) {
  return <KashAuthProvider>{children}</KashAuthProvider>;
}
```

```tsx
// 2. Drop in the connect button (Tailwind required for /ui)
"use client";
import { KashConnect, SignInGate } from "@kashscript/identity-sdk/ui";

export function Header() {
  return <KashConnect variant="outline" compact />;
}

export function Dashboard({ children }: { children: React.ReactNode }) {
  return (
    <SignInGate fallback={<p>Please sign in to continue.</p>}>
      {children}
    </SignInGate>
  );
}
```

```tsx
// 3. Use the identity from anywhere with the hook
"use client";
import { useKashAuth } from "@kashscript/identity-sdk/hooks";

export function Greeting() {
  const { identity } = useKashAuth();
  if (!identity) return null;
  return <p>Hello, {identity.handle ?? identity.did}!</p>;
}
```

That's it. WebAuthn passkey enrollment happens inline, the credential lives
in the browser's secure store, and the DID + handle are persisted to
`localStorage` for fast re-auth on next visit.

---

## What's in the box

| Subpath                              | Purpose                                                     |
|--------------------------------------|-------------------------------------------------------------|
| `@kashscript/identity-sdk`           | Default — re-exports every subpath except `/ui`             |
| `@kashscript/identity-sdk/provider`  | `<KashAuthProvider>` — React Context boundary               |
| `@kashscript/identity-sdk/hooks`     | `useKashAuth()`, `useKashIdentity()`, `useSigner()`        |
| `@kashscript/identity-sdk/webauthn`  | Low-level passkey ceremony helpers (register / authenticate)|
| `@kashscript/identity-sdk/storage`   | Pluggable storage adapter (default: localStorage)           |
| `@kashscript/identity-sdk/errors`    | Typed error classes for all failure paths                   |
| `@kashscript/identity-sdk/ui`        | Tailwind-styled `<KashConnect>`, `<SignInGate>`, `<IdentityWidget>`, `<SignTransactionModal>`, `<ShadowFrame>` |

The `/ui` subpath is **opt-in**. If you don't import from it, no Tailwind
classes or React components ship in your bundle — the SDK stays headless
and ~12 KB gzipped.

---

## Components

### `<KashConnect />`

A single button that drives the full WebAuthn lifecycle:

- Idle, no stored identity → "Create identity"
- Idle, stored identity → "Connect"
- Authenticating → spinner
- Authenticated → connected pill with truncated DID + popover (copy DID / disconnect)
- Error → amber "Try again"

Props:

```typescript
interface KashConnectProps {
  className?: string;
  style?: React.CSSProperties;
  getHandle?: () => Promise<string | null>;  // override window.prompt
  onConnect?: (identity: KashIdentity) => void;
  onDisconnect?: () => void;
  compact?: boolean;                          // icon-only when connected
  variant?: "solid" | "outline" | "ghost";    // for idle state
}
```

### `<SignInGate />`

Render-gate any tree behind authentication.

```tsx
<SignInGate
  fallback={<MarketingLanding />}
  loadingFallback={<Spinner />}
>
  <Dashboard />
</SignInGate>
```

Pair with `<RequireAuth onUnauthorized={() => router.push("/login")}>` for
imperative redirect-style guards.

---

## SSR / Next.js

Every component under `/ui` is marked `"use client"` and respects the
hydration boundary. The default loading fallback is a neutral pulse, so
your first paint is never a layout-shift surprise.

The provider reads `localStorage` only inside `useEffect`, so SSR builds
do not throw. If you SSR-render an authenticated tree, the gate shows the
fallback until the client hydrates the session — set `loadingFallback` to
control that micro-flicker.

---

## License

Apache-2.0. Also covered by SSLA v1.0 Schedule A (Permissive). See [LICENSE](./LICENSE).
