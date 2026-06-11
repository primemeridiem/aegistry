"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
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
		<details>
			<summary>Change password</summary>
			<form
				action={submit}
				style={{ display: "grid", gap: "0.5rem", marginTop: "0.5rem" }}
			>
				{!recoveredViaEmail && (
					<input
						name="current_password"
						type="password"
						placeholder="current password"
					/>
				)}
				<input
					name="new_password"
					type="password"
					placeholder="new password"
					required
				/>
				<button type="submit">Change password</button>
				{message && (
					<p style={{ color: isError ? "crimson" : "seagreen" }}>{message}</p>
				)}
			</form>
		</details>
	);
}
