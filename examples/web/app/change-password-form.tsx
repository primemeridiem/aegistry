"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Label } from "../components/ui/label";
import { auth } from "../lib/auth";

export function ChangePasswordForm({
	hasPassword,
	recoveredViaEmail,
}: {
	hasPassword: boolean;
	recoveredViaEmail: boolean;
}) {
	const router = useRouter();
	const [message, setMessage] = useState<string | null>(null);
	const [isError, setIsError] = useState(false);

	// Three modes:
	// - no password enrolled       -> "Set password", no current-password field
	// - enrolled + OTP-verified    -> "Change password", email proof replaces it
	// - enrolled otherwise         -> "Change password", current password required
	const label = hasPassword ? "Change password" : "Set password";
	const needsCurrent = hasPassword && !recoveredViaEmail;

	async function submit(form: FormData) {
		const currentPassword = String(form.get("current_password") ?? "");
		const { error } = await auth.changePassword({
			newPassword: String(form.get("new_password")),
			currentPassword: currentPassword || undefined,
		});
		if (error) {
			setIsError(true);
			setMessage(error.detail ?? `error ${error.status}`);
			return;
		}
		setIsError(false);
		setMessage(
			hasPassword
				? "Password changed. All other sessions were revoked."
				: "Password set. You can now also sign in with email & password.",
		);
		router.refresh();
	}

	return (
		<details className="border border-border bg-secondary/30 px-3 py-2">
			<summary className="cursor-pointer select-none text-sm text-muted-foreground hover:text-foreground">
				{label}
			</summary>
			<form action={submit} className="grid gap-3 py-3">
				{!hasPassword && (
					<p className="text-xs text-muted-foreground">
						This account signs in without a password. Add one to also sign in
						with email &amp; password.
					</p>
				)}
				{needsCurrent && (
					<div className="grid gap-2">
						<Label htmlFor="current_password">Current password</Label>
						<Input
							id="current_password"
							name="current_password"
							type="password"
							placeholder="current password"
							required
						/>
					</div>
				)}
				{hasPassword && recoveredViaEmail && (
					<p className="text-xs text-blueprint">
						Verified via email code — no current password needed.
					</p>
				)}
				<div className="grid gap-2">
					<Label htmlFor="new_password">New password</Label>
					<Input
						id="new_password"
						name="new_password"
						type="password"
						placeholder="new password"
						required
					/>
				</div>
				<Button type="submit" size="sm">
					{label}
				</Button>
				{message && (
					<p
						className={`text-xs ${isError ? "text-destructive" : "text-blueprint"}`}
					>
						{message}
					</p>
				)}
			</form>
		</details>
	);
}
