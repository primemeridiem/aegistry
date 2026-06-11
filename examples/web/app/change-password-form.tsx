"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Label } from "../components/ui/label";
import { auth } from "../lib/auth";

export function ChangePasswordForm({
	recoveredViaEmail,
}: {
	recoveredViaEmail: boolean;
}) {
	const router = useRouter();
	const [message, setMessage] = useState<string | null>(null);
	const [isError, setIsError] = useState(false);

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
		setMessage("Password changed. All other sessions were revoked.");
		router.refresh();
	}

	return (
		<details className="border border-border bg-secondary/30 px-3 py-2">
			<summary className="cursor-pointer select-none text-sm text-muted-foreground hover:text-foreground">
				Change password
			</summary>
			<form action={submit} className="grid gap-3 py-3">
				{!recoveredViaEmail && (
					<div className="grid gap-2">
						<Label htmlFor="current_password">Current password</Label>
						<Input
							id="current_password"
							name="current_password"
							type="password"
							placeholder="current password"
						/>
					</div>
				)}
				{recoveredViaEmail && (
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
					Change password
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
