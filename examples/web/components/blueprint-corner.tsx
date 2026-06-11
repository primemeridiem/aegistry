/**
 * Decorative blueprint-schematic corner drawing: concentric construction
 * circles, a crosshair, dimension ticks. Fades out radially so the auth card
 * can lean on it the way dash.better-auth.com leans on its world map.
 */
export function BlueprintCorner() {
	return (
		<svg
			aria-hidden="true"
			viewBox="0 0 640 640"
			className="pointer-events-none absolute -left-24 -top-24 size-[560px] select-none text-blueprint opacity-30 [mask-image:radial-gradient(circle_at_top_left,black_30%,transparent_75%)]"
			fill="none"
			stroke="currentColor"
			strokeWidth="1"
		>
			{/* crosshair */}
			<line x1="240" y1="0" x2="240" y2="640" />
			<line x1="0" y1="240" x2="640" y2="240" />
			<circle cx="240" cy="240" r="3" fill="currentColor" stroke="none" />

			{/* construction circles */}
			<circle cx="240" cy="240" r="90" />
			<circle cx="240" cy="240" r="150" strokeDasharray="4 6" />
			<circle cx="240" cy="240" r="215" strokeDasharray="1 7" />

			{/* radius line with end ticks */}
			<line x1="240" y1="240" x2="392" y2="88" />
			<line x1="385" y1="81" x2="399" y2="95" />
			<text
				x="330"
				y="148"
				stroke="none"
				fill="currentColor"
				fontSize="11"
				fontFamily="var(--font-jetbrains-mono), monospace"
			>
				R 215
			</text>

			{/* dimension ruler along the top */}
			<line x1="60" y1="36" x2="420" y2="36" />
			{Array.from({ length: 13 }, (_, i) => 60 + i * 30).map((x) => (
				<line
					key={x}
					x1={x}
					y1="30"
					x2={x}
					y2={x % 90 === 0 ? "46" : "42"}
				/>
			))}

			{/* corner frame */}
			<path d="M 24 200 V 24 H 200" strokeWidth="1.5" />
		</svg>
	);
}
