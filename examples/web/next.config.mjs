const API_URL = process.env.API_URL ?? "http://127.0.0.1:8000";

/** @type {import('next').NextConfig} */
const nextConfig = {
	async rewrites() {
		// Proxy the aegistry routes through this app's origin so session
		// cookies are first-party SameSite=Lax — no CORS configuration needed.
		return [
			{
				source: "/api/auth/:path*",
				destination: `${API_URL}/auth/:path*`,
			},
		];
	},
};

export default nextConfig;
