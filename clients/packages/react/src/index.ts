/**
 * React bindings for the aegistry auth client.
 *
 * ```tsx
 * // lib/auth.ts
 * export const auth = createAuthClient();
 *
 * // component
 * const { data: session, isPending } = auth.useSession();
 * if (session) return <p>signed in as {session.identity_id}</p>;
 * ```
 */

import {
	type AegistrySession,
	type AuthClient,
	type AuthClientOptions,
	createAuthClient as createBaseClient,
} from "@aegistry/client";
import { useStore } from "@nanostores/react";
import { useEffect } from "react";

export type {
	AegistrySession,
	AuthError,
	LoginResponse,
	Result,
} from "@aegistry/client";
export { getServerSession } from "@aegistry/client";

export interface UseSessionResult {
	/** The session, or null when anonymous (or not yet loaded). */
	data: AegistrySession | null;
	/** True until the first session fetch has resolved. */
	isPending: boolean;
	/** Re-fetch the session from the server. */
	refetch: () => Promise<AegistrySession | null>;
}

export interface ReactAuthClient extends AuthClient {
	useSession: () => UseSessionResult;
}

export function createAuthClient(
	options: AuthClientOptions = {},
): ReactAuthClient {
	const client = createBaseClient(options);
	let initialFetchStarted = false;

	function useSession(): UseSessionResult {
		const session = useStore(client.$session);

		useEffect(() => {
			if (!initialFetchStarted && session === undefined) {
				initialFetchStarted = true;
				void client.getSession();
			}
		}, [session]);

		return {
			data: session ?? null,
			isPending: session === undefined,
			refetch: client.getSession,
		};
	}

	return { ...client, useSession };
}
