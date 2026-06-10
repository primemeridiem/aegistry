# aegistry clients

TypeScript SDK for the aegistry FastAPI auth routes.

- **`@aegistry/client`** — framework-agnostic core: typed fetch wrapper,
  reactive `$session` store (nanostores), `getServerSession` for SSR.
- **`@aegistry/react`** — React bindings: `useSession()` hook.

```bash
pnpm install && pnpm build
```

## Recommended setup with Next.js

Proxy the auth routes through your own origin so session cookies are
first-party `SameSite=Lax` — no CORS, no third-party-cookie issues:

```js
// next.config.js
module.exports = {
  async rewrites() {
    return [
      {
        source: "/api/auth/:path*",
        destination: "http://127.0.0.1:8000/auth/:path*",
      },
    ];
  },
};
```

In production, do the same rewrite at your edge, or serve the API on a
sibling subdomain with `AuthConfig(cookie_domain=".example.com")`.

## Usage

```ts
// lib/auth.ts
import { createAuthClient } from "@aegistry/react";

export const auth = createAuthClient(); // baseURL defaults to /api/auth
```

```tsx
"use client";
import { auth } from "@/lib/auth";

export function LoginForm() {
  const { data: session, isPending } = auth.useSession();

  if (isPending) return null;
  if (session) return <button onClick={() => auth.signOut()}>Sign out</button>;

  return (
    <>
      <button onClick={() => auth.signIn.oauth("google")}>Google</button>
      <button onClick={() => auth.signIn.oauth("line")}>LINE</button>
      <form
        action={async (form: FormData) => {
          const { data, error } = await auth.signIn.password({
            email: String(form.get("email")),
            password: String(form.get("password")),
          });
          if (error) {/* show invalid_credentials */}
          else if (data.status === "mfa_required") {/* route to MFA UI */}
        }}
      >
        {/* email + password inputs */}
      </form>
    </>
  );
}
```

Server Components / route handlers / middleware:

```ts
import { getServerSession } from "@aegistry/client";
import { cookies } from "next/headers";

export async function getSession() {
  return getServerSession({
    baseURL: process.env.API_URL + "/auth", // reach FastAPI directly
    cookie: (await cookies()).toString(),
  });
}
```

## Type generation

The request/response types are currently hand-written to match
`aegistry.contrib.fastapi`. Once the route schemas settle, generate them
from FastAPI's `/openapi.json` (e.g. `@hey-api/openapi-ts`) in CI so they
can't drift.
