"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";
import { auth } from "../../lib/auth";

function LoginForm() {
	const router = useRouter();
	const searchParams = useSearchParams();
	const oauthError = searchParams.get("error");

	const [mode, setMode] = useState<"signin" | "signup">("signin");
	const [error, setError] = useState<string | null>(null);
	const [providers, setProviders] = useState<string[]>([]);
	const { data: session, isPending } = auth.useSession();

	useEffect(() => {
		// The demo server reports which OAuth providers have credentials.
		fetch("/api/auth/providers")
			.then((response) => response.json())
			.then((body: { providers: string[] }) => setProviders(body.providers))
			.catch(() => setProviders([]));
	}, []);

	useEffect(() => {
		if (session) {
			router.push("/");
			router.refresh();
		}
	}, [session, router]);

	async function submit(form: FormData) {
		setError(null);
		const credentials = {
			email: String(form.get("email")),
			password: String(form.get("password")),
		};
		const action =
			mode === "signin" ? auth.signIn.password : auth.signUp.password;
		const { data, error } = await action(credentials);
		if (error) {
			setError(error.detail ?? `error ${error.status}`);
			return;
		}
		if (data.status === "mfa_required") {
			setError(`MFA required: ${data.factors.join(", ")} (not in this demo UI)`);
			return;
		}
		router.push("/");
		router.refresh();
	}

	if (isPending || session) return null;

	return (
		<main>
			<h1>aegistry demo — {mode === "signin" ? "sign in" : "sign up"}</h1>

			{oauthError && (
				<p style={{ color: "crimson" }}>OAuth error: {oauthError}</p>
			)}
			{error && <p style={{ color: "crimson" }}>{error}</p>}

			<form action={submit} style={{ display: "grid", gap: "0.5rem" }}>
				<input name="email" type="email" placeholder="email" required />
				<input
					name="password"
					type="password"
					placeholder="password"
					required
				/>
				<button type="submit">
					{mode === "signin" ? "Sign in" : "Create account"}
				</button>
			</form>

			<p>
				<button
					type="button"
					onClick={() => setMode(mode === "signin" ? "signup" : "signin")}
				>
					{mode === "signin"
						? "Need an account? Sign up"
						: "Have an account? Sign in"}
				</button>
			</p>

			{providers.length > 0 && (
				<>
					<hr />
					<div style={{ display: "grid", gap: "0.5rem" }}>
						{providers.map((provider) => (
							<button
								key={provider}
								type="button"
								onClick={() => auth.signIn.oauth(provider)}
							>
								Continue with {provider === "line" ? "LINE" : "Google"}
							</button>
						))}
					</div>
				</>
			)}
		</main>
	);
}

export default function LoginPage() {
	return (
		<Suspense>
			<LoginForm />
		</Suspense>
	);
}
