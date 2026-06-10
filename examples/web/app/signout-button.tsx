"use client";

import { useRouter } from "next/navigation";
import { auth } from "../lib/auth";

export function SignOutButton() {
	const router = useRouter();

	return (
		<button
			type="button"
			onClick={async () => {
				await auth.signOut();
				router.push("/login");
				router.refresh();
			}}
		>
			Sign out
		</button>
	);
}
