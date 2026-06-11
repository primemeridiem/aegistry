# @aegistry/react

React bindings for [`@aegistry/client`](https://www.npmjs.com/package/@aegistry/client), the TypeScript client for [aegistry](https://github.com/primemeridiem/aegistry) — the FastAPI authentication library.

```bash
npm install @aegistry/react
```

## Usage

```ts
// lib/auth.ts
import { createAuthClient } from "@aegistry/react";

export const auth = createAuthClient();
export const { useSession } = auth;
```

```tsx
"use client";

import { auth, useSession } from "../lib/auth";

export function UserMenu() {
  const { data: session, isPending } = useSession();

  if (isPending) return <span>…</span>;
  if (!session) return <a href="/login">Sign in</a>;

  return <button onClick={() => auth.signOut()}>Sign out</button>;
}
```

`createAuthClient` re-exports everything from `@aegistry/client` (password, email OTP, and OAuth sign-in; `changePassword`; `signOut`) and adds the `useSession()` hook, which subscribes to the shared session store and re-renders on auth changes.

See the [aegistry repository](https://github.com/primemeridiem/aegistry) for the FastAPI side and a full Next.js example.
