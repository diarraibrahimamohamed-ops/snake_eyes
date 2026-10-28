/** @type {import("next").NextConfig} */
const apiBaseUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

const nextConfig = {
  output: "standalone",
  images: { domains: ["localhost"] },
  async rewrites() {
    return [{
      source: "/api/:path*",
      destination: `${apiBaseUrl}/api/:path*`,
    }];
  },
};
module.exports = nextConfig;
