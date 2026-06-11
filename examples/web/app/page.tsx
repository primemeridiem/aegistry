import { redirect } from "next/navigation";
import { BlueprintCorner } from "../components/blueprint-corner";
import { getMe, getSession } from "../lib/session";
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

	const me = await getMe();

	return (
		<main className="relative flex min-h-dvh justify-center overflow-hidden bg-blueprint-grid p-4 pt-[14vh]">
			<BlueprintCorner />
			<div className="relative w-full max-w-md">
				<p className="mb-6 text-center font-display text-3xl tracking-wide text-blueprint">
					AEGISTRY
				</p>
				<Card className="shadow-xl shadow-black/40">
					<CardHeader className="flex-row items-center gap-4">
						{me?.picture_url ? (
							// eslint-disable-next-line @next/next/no-img-element
							<img
								src={me.picture_url}
								alt=""
								className="size-12 rounded-full border border-border"
							/>
						) : (
							<div className="grid size-12 place-items-center rounded-full border border-border bg-secondary font-display text-xl text-blueprint">
								{(me?.name ?? me?.email ?? "?").charAt(0).toUpperCase()}
							</div>
						)}
						<div className="grid gap-1">
							<CardTitle>{me?.name ?? me?.email ?? "Signed in"}</CardTitle>
							<CardDescription>
								{me?.name ? me.email : "Server-rendered from the session cookie"}
							</CardDescription>
						</div>
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
							hasPassword={me?.has_password ?? false}
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
