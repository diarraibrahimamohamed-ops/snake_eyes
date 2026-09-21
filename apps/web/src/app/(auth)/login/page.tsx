"use client";
import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Shield, Eye, EyeOff, Loader2 } from "lucide-react";
import { useAuthStore } from "@/lib/stores/auth";
import { useRouter, useSearchParams } from "next/navigation";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [show, setShow] = useState(false);
  const [error, setError] = useState("");
  const { login, isLoading, isAuthenticated } = useAuthStore();
  const router = useRouter();
  const searchParams = useSearchParams();

  // Si déjà connecté, rediriger
  useEffect(() => {
    if (isAuthenticated) {
      const redirect = searchParams.get("redirect") || "/dashboard";
      router.replace(redirect);
    }
  }, [isAuthenticated, router, searchParams]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    try {
      await login(email, password);
      const redirect = searchParams.get("redirect") || "/dashboard";
      router.replace(redirect);
    } catch (err: any) {
      const msg =
        err?.response?.data?.detail ||
        err?.response?.data?.message ||
        "Identifiants incorrects. Vérifiez votre email et mot de passe.";
      setError(msg);
    }
  }

  return (
    <div className="min-h-screen bg-[#060d1a] flex items-center justify-center p-4">
      {/* Grille de fond */}
      <div
        className="absolute inset-0 opacity-5"
        style={{
          backgroundImage:
            "linear-gradient(rgba(0,229,255,.3) 1px,transparent 1px),linear-gradient(90deg,rgba(0,229,255,.3) 1px,transparent 1px)",
          backgroundSize: "50px 50px",
        }}
      />

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-md relative z-10"
      >
        <div className="bg-[#0a1628]/90 border border-cyan-900/50 rounded-sm p-8 backdrop-blur-sm">
          {/* Coins décoratifs */}
          {[
            "top-0 left-0 border-t border-l",
            "top-0 right-0 border-t border-r",
            "bottom-0 left-0 border-b border-l",
            "bottom-0 right-0 border-b border-r",
          ].map((c, i) => (
            <div key={i} className={`absolute w-4 h-4 ${c} border-cyan-500/60`} />
          ))}

          {/* Logo */}
          <div className="flex flex-col items-center mb-8">
            <div className="relative mb-3">
              <Shield className="w-12 h-12 text-cyan-400" />
              <motion.div
                className="absolute inset-0 border border-cyan-400/30 rounded-full"
                animate={{ scale: [1, 1.5], opacity: [0.5, 0] }}
                transition={{ duration: 2, repeat: Infinity }}
              />
            </div>
            <h1 className="text-xl font-bold tracking-[0.3em] text-cyan-400">
              AFRICANWATCH
            </h1>
            <p className="text-[10px] text-cyan-600 tracking-widest mt-1">
              CYBER INTELLIGENCE PLATFORM
            </p>
          </div>

          {/* Formulaire */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-[10px] text-cyan-500 tracking-widest mb-1.5">
                EMAIL
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoComplete="email"
                className="w-full bg-[#060d1a] border border-cyan-900/50 text-cyan-100 text-sm px-3 py-2.5 rounded-sm focus:outline-none focus:border-cyan-500/50 placeholder:text-gray-600 font-mono"
                placeholder="vous@example.com"
              />
            </div>

            <div>
              <label className="block text-[10px] text-cyan-500 tracking-widest mb-1.5">
                MOT DE PASSE
              </label>
              <div className="relative">
                <input
                  type={show ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  autoComplete="current-password"
                  className="w-full bg-[#060d1a] border border-cyan-900/50 text-cyan-100 text-sm px-3 py-2.5 pr-10 rounded-sm focus:outline-none focus:border-cyan-500/50 placeholder:text-gray-600 font-mono"
                  placeholder="••••••••••••"
                />
                <button
                  type="button"
                  onClick={() => setShow(!show)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-cyan-400"
                >
                  {show ? (
                    <EyeOff className="w-4 h-4" />
                  ) : (
                    <Eye className="w-4 h-4" />
                  )}
                </button>
              </div>
            </div>

            {error && (
              <motion.div
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                className="text-red-400 text-[11px] font-mono bg-red-400/10 border border-red-400/20 px-3 py-2 rounded-sm"
              >
                ⚠ {error}
              </motion.div>
            )}

            <button
              type="submit"
              disabled={isLoading}
              className="w-full bg-cyan-500/10 border border-cyan-500/50 text-cyan-400 font-bold tracking-[0.2em] text-sm py-3 rounded-sm hover:bg-cyan-500/20 hover:border-cyan-400 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 mt-6"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  AUTHENTIFICATION...
                </>
              ) : (
                "ACCÉDER AU SYSTÈME"
              )}
            </button>
          </form>

          <p className="text-center text-[10px] text-gray-600 mt-6 font-mono">
            AfricaWatch v1.0 — Accès réservé aux personnes autorisées
          </p>
        </div>
      </motion.div>
    </div>
  );
}
