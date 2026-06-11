/**
 * Framework-agnostic client for the aegistry FastAPI auth routes.
 *
 * Sessions live in httpOnly cookies set by the server, so this client never
 * touches tokens — it only calls the JSON endpoints with
 * `credentials: "include"` and tracks the session state in a nanostores
 * atom that framework bindings (e.g. `@aegistry/react`) can subscribe to.
 */

import { atom, type ReadableAtom, type WritableAtom } from "nanostores";

/** Session metadata returned by `GET /session`. */
export interface AegistrySession {
	identity_id: string | number;
	amr: string[];
	expires_at: number;
}

/** Response of `POST /login` and `POST /register`. */
export interface LoginResponse {
	status: "complete" | "mfa_required";
	factors: string[];
}

export interface AuthError {
	status: number;
	detail: string | null;
}

export type Result<T> =
	| { data: T; error: null }
	| { data: null; error: AuthError };

export interface AuthClientOptions {
	/**
	 * Base URL of the aegistry routes. Defaults to "/api/auth", the
	 * recommended same-origin proxy path (e.g. a Next.js rewrite).
	 * Use an absolute URL only for cross-origin setups with CORS configured.
	 */
	baseURL?: string;
	/** Custom fetch implementation (tests, SSR runtimes). */
	fetch?: typeof globalThis.fetch;
}

export interface AuthClient {
	/**
	 * Reactive session state: `undefined` until the first fetch resolves,
	 * `null` when anonymous, otherwise the session.
	 */
	$session: ReadableAtom<AegistrySession | null | undefined>;
	/** Fetch the current session from the server and update `$session`. */
	getSession: () => Promise<AegistrySession | null>;
	signIn: {
		/** Email/password login. Refreshes `$session` when login completes. */
		password: (credentials: {
			email: string;
			password: string;
		}) => Promise<Result<LoginResponse>>;
		/**
		 * Email OTP (passwordless) login. Also the password-recovery entry
		 * point: after verify, the session's AMR includes "email", which
		 * lets changePassword run without the current password.
		 */
		emailOtp: {
			/** Send a one-time code. Same response whether the email exists. */
			request: (input: { email: string }) => Promise<Result<null>>;
			/** Verify the code. Refreshes `$session` when login completes. */
			verify: (input: { code: string }) => Promise<Result<LoginResponse>>;
		};
		/**
		 * Start an OAuth login by navigating to the provider authorize route.
		 * Browser only. The server redirects back to its configured
		 * `success_redirect_url` when the flow completes.
		 */
		oauth: (provider: string) => void;
	};
	signUp: {
		/** Email/password registration. Refreshes `$session` on completion. */
		password: (credentials: {
			email: string;
			password: string;
		}) => Promise<Result<LoginResponse>>;
	};
	/**
	 * Change (or set) the password. Requires either `currentPassword` or a
	 * session authenticated via email OTP. The server revokes all sessions
	 * and issues a fresh cookie.
	 */
	changePassword: (input: {
		newPassword: string;
		currentPassword?: string;
	}) => Promise<Result<null>>;
	/** Revoke the session server-side and clear the local state. */
	signOut: () => Promise<void>;
}

async function toError(response: Response): Promise<AuthError> {
	let detail: string | null = null;
	try {
		const body = (await response.json()) as { detail?: unknown };
		if (typeof body.detail === "string") detail = body.detail;
	} catch {
		// non-JSON error body
	}
	return { status: response.status, detail };
}

export function createAuthClient(options: AuthClientOptions = {}): AuthClient {
	const baseURL = (options.baseURL ?? "/api/auth").replace(/\/+$/, "");
	const fetchFn = options.fetch ?? globalThis.fetch.bind(globalThis);

	const $session: WritableAtom<AegistrySession | null | undefined> =
		atom(undefined);

	async function getSession(): Promise<AegistrySession | null> {
		try {
			const response = await fetchFn(`${baseURL}/session`, {
				credentials: "include",
			});
			const session = response.ok
				? ((await response.json()) as AegistrySession)
				: null;
			$session.set(session);
			return session;
		} catch {
			$session.set(null);
			return null;
		}
	}

	async function jsonPost(
		path: string,
		body: Record<string, unknown>,
	): Promise<Response> {
		return fetchFn(`${baseURL}${path}`, {
			method: "POST",
			credentials: "include",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(body),
		});
	}

	async function loginRequest(
		path: string,
		body: Record<string, unknown>,
	): Promise<Result<LoginResponse>> {
		const response = await jsonPost(path, body);
		if (!response.ok) {
			return { data: null, error: await toError(response) };
		}
		const data = (await response.json()) as LoginResponse;
		if (data.status === "complete") {
			await getSession();
		}
		return { data, error: null };
	}

	return {
		$session,
		getSession,
		signIn: {
			password: (credentials) => loginRequest("/login", credentials),
			emailOtp: {
				request: async ({ email }) => {
					const response = await jsonPost("/email-otp/request", { email });
					if (!response.ok) {
						return { data: null, error: await toError(response) };
					}
					return { data: null, error: null };
				},
				verify: ({ code }) => loginRequest("/email-otp/verify", { code }),
			},
			oauth: (provider) => {
				if (typeof window === "undefined") {
					throw new Error("signIn.oauth is browser-only");
				}
				window.location.href = `${baseURL}/${provider}/authorize`;
			},
		},
		signUp: {
			password: (credentials) => loginRequest("/register", credentials),
		},
		changePassword: async ({ newPassword, currentPassword }) => {
			const response = await jsonPost("/change-password", {
				new_password: newPassword,
				current_password: currentPassword ?? null,
			});
			if (!response.ok) {
				return { data: null, error: await toError(response) };
			}
			return { data: null, error: null };
		},
		signOut: async () => {
			await fetchFn(`${baseURL}/logout`, {
				method: "POST",
				credentials: "include",
			});
			$session.set(null);
		},
	};
}

export interface ServerSessionOptions {
	/** Absolute URL of the aegistry routes as reachable from the server. */
	baseURL: string;
	/** The incoming request's Cookie header value. */
	cookie: string;
	fetch?: typeof globalThis.fetch;
}

/**
 * Fetch the session server-side by forwarding the incoming request's
 * cookies — for SSR, Server Components, and middleware. Framework-neutral:
 * in Next.js, pass `(await cookies()).toString()`.
 */
export async function getServerSession(
	options: ServerSessionOptions,
): Promise<AegistrySession | null> {
	const baseURL = options.baseURL.replace(/\/+$/, "");
	const fetchFn = options.fetch ?? globalThis.fetch.bind(globalThis);
	const response = await fetchFn(`${baseURL}/session`, {
		headers: { cookie: options.cookie },
		cache: "no-store",
	});
	if (!response.ok) return null;
	return (await response.json()) as AegistrySession;
}
