import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AfricaWatch — Cyber Intelligence Platform",
  description: "Plateforme africaine de cybersécurité, threat intelligence et OSINT",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="fr">
      <body className="bg-[#060d1a] text-white antialiased">{children}</body>
    </html>
  );
}
