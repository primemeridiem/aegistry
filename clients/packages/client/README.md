# @aegistry/client

Framework-agnostic TypeScript client for [aegistry](https://github.com/primemeridiem/aegistry), the FastAPI authentication library. Talks to the aegistry FastAPI routers over their cookie-based HTTP API and exposes a reactive session store powered by [nanostores](https://github.com/nanostores/nanostores).

```bash
npm install @aegistry/client
```

## Usage

```ts
import { createAuthClient } from "@aegistry/client";

// baseURL defaults to "/api/auth" — pair it with a reverse-proxy rewrite
// to your FastAPI backend so cookies stay first-party.
export const auth = createAuthClient();

await auth.signUp.password({ email: "a@b.co", password: "hunter22" });
await auth.signIn.password({ email: "a@b.co", password: "hunter22" });

// Email OTP (passwordless / forgot password)
await auth.signIn.emailOtp.request({ email: "a@b.co" });
await auth.signIn.emailOtp.verify({ email: "a@b.co", code: "ABC123" });

// OAuth — full-page redirect to the provider
auth.signIn.oauth("google");

const session = await auth.getSession();
await auth.changePassword({ newPassword: "hunter23", currentPassword: "hunter22" });
await auth.signOut();
```

For server-side rendering, `getServerSession` resolves a session by forwarding cookies directly to the backend:

```ts
import { getServerSession } from "@aegistry/client";

const session = await getServerSession({
  baseURL: "http://127.0.0.1:8000/auth",
  cookie: requestCookieHeader,
});
```

React bindings live in [`@aegistry/react`](https://www.npmjs.com/package/@aegistry/react). See the [aegistry repository](https://github.com/primemeridiem/aegistry) for the FastAPI side and a full Next.js example.
