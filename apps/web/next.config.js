/** @type {import("next").NextConfig} */
const nextConfig = {
  output: "standalone",
  images: { domains: ["localhost"] },
  async rewrites() {
    return [{
      source: "/api/:path*",
      destination: `${process.env.NEXT_PUBLIC_API_URL}/api/:path*`,
    }];
  },
};
module.exports = nextConfig;
