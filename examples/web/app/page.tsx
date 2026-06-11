import { redirect } from "next/navigation";
import { getSession } from "../lib/session";
import { ChangePasswordForm } from "./change-password-form";
import { SignOutButton } from "./signout-button";
import {
	Card,
	CardContent,
	CardDescription,
	CardFooter,
	CardHeader,
	CardTitle,
} from "../components/ui/card";

// Server Component: the session is resolved server-side by forwarding the
// request cookies to FastAPI (see lib/session.ts).
export default async function Home() {
	const session = await getSession();

	if (!session) {
		redirect("/login");
	}

	return (
		<main className="grid min-h-dvh place-items-center bg-blueprint-grid p-4">
			<div className="w-full max-w-sm">
				<p className="mb-6 text-center font-display text-3xl tracking-wide text-blueprint">
					AEGISTRY
				</p>
				<Card>
					<CardHeader>
						<CardTitle>Signed in</CardTitle>
						<CardDescription>
							Server-rendered from the session cookie
						</CardDescription>
					</CardHeader>
					<CardContent className="grid gap-3 text-sm">
						<dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2">
							<dt className="text-muted-foreground">Identity</dt>
							<dd>{session.identity_id}</dd>
							<dt className="text-muted-foreground">Methods</dt>
							<dd className="font-mono text-blueprint">
								{session.amr.join(", ")}
							</dd>
							<dt className="text-muted-foreground">Expires</dt>
							<dd>{new Date(session.expires_at * 1000).toLocaleString()}</dd>
						</dl>
						<ChangePasswordForm
							recoveredViaEmail={session.amr.includes("email")}
						/>
					</CardContent>
					<CardFooter className="border-t border-border pt-4">
						<SignOutButton />
					</CardFooter>
				</Card>
			</div>
		</main>
	);
}
