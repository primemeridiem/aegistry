import type { ReactNode } from "react";

export const metadata = {
	title: "aegistry demo",
};

export default function RootLayout({ children }: { children: ReactNode }) {
	return (
		<html lang="en">
			<body
				style={{
					fontFamily: "ui-sans-serif, system-ui, sans-serif",
					maxWidth: 480,
					margin: "4rem auto",
					padding: "0 1rem",
					lineHeight: 1.6,
				}}
			>
				{children}
			</body>
		</html>
	);
}
