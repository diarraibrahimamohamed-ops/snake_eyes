import type { Config } from "tailwindcss";
const config: Config = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        aw: {
          bg: "#060d1a", panel: "#0a1628", border: "#0e2a4a",
          cyan: "#00e5ff", red: "#ef4444", orange: "#f97316",
          green: "#22c55e", purple: "#a855f7", yellow: "#eab308",
        },
      },
      fontFamily: { mono: ["JetBrains Mono","Fira Code","monospace"] },
    },
  },
  plugins: [],
};
export default config;
