"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";
import { auth } from "../../lib/auth";

type Mode = "signin" | "signup" | "email-otp";

function LoginForm() {
	const router = useRouter();
	const searchParams = useSearchParams();
	const oauthError = searchParams.get("error");

	const [mode, setMode] = useState<Mode>("signin");
	const [otpSent, setOtpSent] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [info, setInfo] = useState<string | null>(null);
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

	async function submitPassword(form: FormData) {
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

	async function requestCode(form: FormData) {
		setError(null);
		const { error } = await auth.signIn.emailOtp.request({
			email: String(form.get("email")),
		});
		if (error) {
			setError(error.detail ?? `error ${error.status}`);
			return;
		}
		setOtpSent(true);
		setInfo("Code sent — check the backend terminal in this demo.");
	}

	async function verifyCode(form: FormData) {
		setError(null);
		const { data, error } = await auth.signIn.emailOtp.verify({
			code: String(form.get("code")),
		});
		if (error) {
			setError(error.detail ?? `error ${error.status}`);
			return;
		}
		if (data.status === "complete") {
			router.push("/");
			router.refresh();
		}
	}

	if (isPending || session) return null;

	return (
		<main>
			<h1>aegistry demo</h1>

			{oauthError && (
				<p style={{ color: "crimson" }}>OAuth error: {oauthError}</p>
			)}
			{error && <p style={{ color: "crimson" }}>{error}</p>}
			{info && !error && <p style={{ color: "seagreen" }}>{info}</p>}

			{mode !== "email-otp" ? (
				<form action={submitPassword} style={{ display: "grid", gap: "0.5rem" }}>
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
			) : !otpSent ? (
				<form action={requestCode} style={{ display: "grid", gap: "0.5rem" }}>
					<input name="email" type="email" placeholder="email" required />
					<button type="submit">Send login code</button>
				</form>
			) : (
				<form action={verifyCode} style={{ display: "grid", gap: "0.5rem" }}>
					<input name="code" placeholder="6-character code" required />
					<button type="submit">Verify code</button>
					<button type="button" onClick={() => setOtpSent(false)}>
						Use a different email
					</button>
				</form>
			)}

			<p style={{ display: "grid", gap: "0.25rem", justifyItems: "start" }}>
				{mode !== "signin" && (
					<button type="button" onClick={() => setMode("signin")}>
						Sign in with password
					</button>
				)}
				{mode !== "signup" && (
					<button type="button" onClick={() => setMode("signup")}>
						Create an account
					</button>
				)}
				{mode !== "email-otp" && (
					<button
						type="button"
						onClick={() => {
							setMode("email-otp");
							setOtpSent(false);
							setInfo(null);
						}}
					>
						Email me a login code (also: forgot password)
					</button>
				)}
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
