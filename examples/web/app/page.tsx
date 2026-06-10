import Link from "next/link";
import { redirect } from "next/navigation";
import { getSession } from "../lib/session";
import { SignOutButton } from "./signout-button";

// Server Component: the session is resolved server-side by forwarding the
// request cookies to FastAPI (see lib/session.ts).
export default async function Home() {
	const session = await getSession();

	if (!session) {
		redirect("/login");
	}

	return (
		<main>
			<h1>aegistry demo</h1>
			<p>
				Signed in as identity <strong>{session.identity_id}</strong>
			</p>
			<p>
				Authentication methods: <code>{session.amr.join(", ")}</code>
				<br />
				Session expires:{" "}
				{new Date(session.expires_at * 1000).toLocaleString()}
			</p>
			<SignOutButton />
			<p>
				<Link href="/login">Login page</Link>
			</p>
		</main>
	);
}
