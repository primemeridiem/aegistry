import { createAuthClient } from "@aegistry/react";

// baseURL defaults to /api/auth — proxied to FastAPI by next.config.mjs.
export const auth = createAuthClient();
