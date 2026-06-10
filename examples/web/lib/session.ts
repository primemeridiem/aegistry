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
