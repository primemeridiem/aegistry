"use client";

import { Eye, EyeOff } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";
import { BlueprintCorner } from "../../components/blueprint-corner";
import { GoogleIcon, LineIcon } from "../../components/provider-icons";
import { Button } from "../../components/ui/button";
import {
	Card,
	CardContent,
	CardDescription,
	CardFooter,
	CardHeader,
	CardTitle,
} from "../../components/ui/card";
import { Checkbox } from "../../components/ui/checkbox";
import { Input } from "../../components/ui/input";
import { Label } from "../../components/ui/label";
import {
	Tabs,
	TabsContent,
	TabsList,
	TabsTrigger,
} from "../../components/ui/tabs";
import { auth } from "../../lib/auth";

type View = "password" | "otp-request" | "otp-verify";

function PasswordInput({ name }: { name: string }) {
	const [visible, setVisible] = useState(false);
	return (
		<div className="relative">
			<Input
				id={name}
				name={name}
				type={visible ? "text" : "password"}
				placeholder="password"
				required
				className="pr-10"
			/>
			<button
				type="button"
				tabIndex={-1}
				aria-label={visible ? "Hide password" : "Show password"}
				onClick={() => setVisible(!visible)}
				className="absolute inset-y-0 right-0 flex w-10 items-center justify-center text-muted-foreground hover:text-foreground"
			>
				{visible ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
			</button>
		</div>
	);
}

function OAuthButtons({ providers }: { providers: string[] }) {
	if (providers.length === 0) return null;
	return (
		<div className="grid gap-2 border-t border-border pt-4">
			{providers.includes("google") && (
				<Button
					type="button"
					variant="outline"
					className="w-full"
					onClick={() => auth.signIn.oauth("google")}
				>
					<GoogleIcon />
					Sign in with Google
				</Button>
			)}
			{providers.includes("line") && (
				<Button
					type="button"
					variant="outline"
					className="w-full"
					onClick={() => auth.signIn.oauth("line")}
				>
					<LineIcon />
					Sign in with LINE
				</Button>
			)}
		</div>
	);
}

function TermsFooter() {
	return (
		<CardFooter className="justify-center border-t border-border pt-4 [&>p]:text-center">
			<p className="text-xs text-muted-foreground">
				By signing in, you agree to the{" "}
				<a href="#terms" className="underline underline-offset-2 hover:text-foreground">
					Terms of Service
				</a>{" "}
				and{" "}
				<a href="#privacy" className="underline underline-offset-2 hover:text-foreground">
					Privacy Policy
				</a>
				.
			</p>
		</CardFooter>
	);
}

function LoginForm() {
	const router = useRouter();
	const searchParams = useSearchParams();
	const oauthError = searchParams.get("error");

	const [view, setView] = useState<View>("password");
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

	function handleLoginResult(
		data: { status: string; factors: string[] } | null,
		err: { status: number; detail: string | null } | null,
	) {
		if (err) {
			setError(err.detail ?? `error ${err.status}`);
			return;
		}
		if (data?.status === "mfa_required") {
			setError(`MFA required: ${data.factors.join(", ")} (not in this demo UI)`);
			return;
		}
		router.push("/");
		router.refresh();
	}

	async function submitSignIn(form: FormData) {
		setError(null);
		const { data, error } = await auth.signIn.password({
			email: String(form.get("email")),
			password: String(form.get("password")),
		});
		handleLoginResult(data, error);
	}

	async function submitSignUp(form: FormData) {
		setError(null);
		const { data, error } = await auth.signUp.password({
			email: String(form.get("email")),
			password: String(form.get("signup-password")),
		});
		handleLoginResult(data, error);
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
		setInfo("Code sent — check the backend terminal in this demo.");
		setView("otp-verify");
	}

	async function verifyCode(form: FormData) {
		setError(null);
		const { data, error } = await auth.signIn.emailOtp.verify({
			code: String(form.get("code")),
		});
		handleLoginResult(data, error);
	}

	if (isPending || session) return null;

	const alerts = (
		<>
			{oauthError && !error && (
				<p className="border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
					OAuth error: {oauthError}
				</p>
			)}
			{error && (
				<p className="border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
					{error}
				</p>
			)}
			{info && !error && (
				<p className="border border-blueprint/40 bg-blueprint/10 px-3 py-2 text-xs text-blueprint">
					{info}
				</p>
			)}
		</>
	);

	return (
		<main className="relative flex min-h-dvh justify-center overflow-hidden bg-blueprint-grid p-4 pt-[14vh]">
			<BlueprintCorner />
			<div className="relative w-full max-w-md">
				<p className="mb-6 text-center font-display text-3xl tracking-wide text-blueprint">
					AEGISTRY
				</p>

				<Tabs
					defaultValue="signin"
					onValueChange={() => {
						setError(null);
						setInfo(null);
						setView("password");
					}}
				>
					<TabsList>
						<TabsTrigger value="signin">Sign In</TabsTrigger>
						<TabsTrigger value="signup">Sign Up</TabsTrigger>
					</TabsList>

					<TabsContent value="signin" className="-mt-px">
						<Card className="rounded-tl-none shadow-xl shadow-black/40">
							{view === "password" && (
								<>
									<CardHeader>
										<CardTitle>Sign In</CardTitle>
										<CardDescription>
											Enter your email below to login to your account
										</CardDescription>
									</CardHeader>
									<CardContent className="grid gap-4">
										{alerts}
										<form action={submitSignIn} className="grid gap-4">
											<div className="grid gap-2">
												<Label htmlFor="email">Email</Label>
												<Input
													id="email"
													name="email"
													type="email"
													placeholder="m@example.com"
													required
												/>
											</div>
											<div className="grid gap-2">
												<div className="flex items-center justify-between">
													<Label htmlFor="password">Password</Label>
													<button
														type="button"
														onClick={() => {
															setError(null);
															setInfo(null);
															setView("otp-request");
														}}
														className="text-sm underline underline-offset-4 hover:text-blueprint"
													>
														Forgot your password?
													</button>
												</div>
												<PasswordInput name="password" />
											</div>
											<div className="flex items-center gap-2">
												<Checkbox id="remember" name="remember" />
												<Label
													htmlFor="remember"
													className="font-normal text-muted-foreground"
												>
													Remember me
												</Label>
											</div>
											<Button type="submit" className="w-full">
												Login
											</Button>
										</form>
										<OAuthButtons providers={providers} />
									</CardContent>
									<TermsFooter />
								</>
							)}

							{view === "otp-request" && (
								<>
									<CardHeader>
										<CardTitle>Reset access</CardTitle>
										<CardDescription>
											We&apos;ll email you a one-time login code. After signing
											in you can set a new password.
										</CardDescription>
									</CardHeader>
									<CardContent className="grid gap-4">
										{alerts}
										<form action={requestCode} className="grid gap-4">
											<div className="grid gap-2">
												<Label htmlFor="otp-email">Email</Label>
												<Input
													id="otp-email"
													name="email"
													type="email"
													placeholder="m@example.com"
													required
												/>
											</div>
											<Button type="submit" className="w-full">
												Send login code
											</Button>
											<Button
												type="button"
												variant="ghost"
												onClick={() => setView("password")}
											>
												Back to sign in
											</Button>
										</form>
									</CardContent>
								</>
							)}

							{view === "otp-verify" && (
								<>
									<CardHeader>
										<CardTitle>Enter code</CardTitle>
										<CardDescription>
											Type the 6-character code we sent to your email.
										</CardDescription>
									</CardHeader>
									<CardContent className="grid gap-4">
										{alerts}
										<form action={verifyCode} className="grid gap-4">
											<div className="grid gap-2">
												<Label htmlFor="code">Login code</Label>
												<Input
													id="code"
													name="code"
													placeholder="ABC123"
													autoComplete="one-time-code"
													className="tracking-[0.3em] uppercase"
													required
												/>
											</div>
											<Button type="submit" className="w-full">
												Verify code
											</Button>
											<Button
												type="button"
												variant="ghost"
												onClick={() => setView("otp-request")}
											>
												Use a different email
											</Button>
										</form>
									</CardContent>
								</>
							)}
						</Card>
					</TabsContent>

					<TabsContent value="signup" className="-mt-px">
						<Card className="rounded-tl-none shadow-xl shadow-black/40">
							<CardHeader>
								<CardTitle>Sign Up</CardTitle>
								<CardDescription>
									Create a new account with your email and a password
								</CardDescription>
							</CardHeader>
							<CardContent className="grid gap-4">
								{alerts}
								<form action={submitSignUp} className="grid gap-4">
									<div className="grid gap-2">
										<Label htmlFor="signup-email">Email</Label>
										<Input
											id="signup-email"
											name="email"
											type="email"
											placeholder="m@example.com"
											required
										/>
									</div>
									<div className="grid gap-2">
										<Label htmlFor="signup-password">Password</Label>
										<PasswordInput name="signup-password" />
									</div>
									<Button type="submit" className="w-full">
										Create account
									</Button>
								</form>
								<OAuthButtons providers={providers} />
							</CardContent>
							<TermsFooter />
						</Card>
					</TabsContent>
				</Tabs>
			</div>
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
