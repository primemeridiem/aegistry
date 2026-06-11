import { JetBrains_Mono, Source_Serif_4, VT323 } from "next/font/google";
import type { ReactNode } from "react";
import "./globals.css";

const jetbrainsMono = JetBrains_Mono({
	subsets: ["latin"],
	variable: "--font-jetbrains-mono",
});

const vt323 = VT323({
	weight: "400",
	subsets: ["latin"],
	variable: "--font-vt323",
});

const sourceSerif = Source_Serif_4({
	subsets: ["latin"],
	variable: "--font-source-serif",
});

export const metadata = {
	title: "aegistry demo",
};

export default function RootLayout({ children }: { children: ReactNode }) {
	return (
		<html
			lang="en"
			className={`${jetbrainsMono.variable} ${vt323.variable} ${sourceSerif.variable}`}
		>
			<body className="min-h-dvh antialiased">{children}</body>
		</html>
	);
}
