import { getServerSession } from "@aegistry/client";
import { cookies } from "next/headers";

const API_URL = process.env.API_URL ?? "http://127.0.0.1:8000";

/** Server-side session lookup for Server Components and route handlers. */
export async function getSession() {
	return getServerSession({
		baseURL: `${API_URL}/auth`,
		cookie: (await cookies()).toString(),
	});
}

export interface Me {
	id: number;
	email: string;
	name: string | null;
	picture_url: string | null;
	has_password: boolean;
}

/** Server-side user lookup against the demo's app-level /auth/me endpoint. */
export async function getMe(): Promise<Me | null> {
	const response = await fetch(`${API_URL}/auth/me`, {
		headers: { cookie: (await cookies()).toString() },
		cache: "no-store",
	});
	if (!response.ok) return null;
	return (await response.json()) as Me;
}
