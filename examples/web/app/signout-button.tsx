"use client";

import { useRouter } from "next/navigation";
import { Button } from "../components/ui/button";
import { auth } from "../lib/auth";

export function SignOutButton() {
	const router = useRouter();

	return (
		<Button
			type="button"
			variant="outline"
			className="w-full"
			onClick={async () => {
				await auth.signOut();
				router.push("/login");
				router.refresh();
			}}
		>
			Sign out
		</Button>
	);
}
