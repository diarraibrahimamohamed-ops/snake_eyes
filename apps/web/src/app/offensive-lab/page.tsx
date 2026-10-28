"use client";

import Link from "next/link";
import { ArrowRight, FileSearch, ShieldAlert, ShieldCheck, Workflow } from "lucide-react";
import AppLayout from "@/components/layout/Sidebar";

export default function DefensiveAssessmentNotice() {
  return (
    <AppLayout>
      <main className="mx-auto max-w-5xl space-y-6 p-6 lg:p-10">
        <div className="flex items-center gap-3 text-cyan-300">
          <ShieldCheck className="h-6 w-6" />
          <span className="text-xs font-semibold tracking-[0.22em]">POLITIQUE DE SÉCURITÉ INSTITUTIONNELLE</span>
        </div>
        <section className="rounded-2xl border border-cyan-800/40 bg-slate-900/80 p-7 md:p-10">
          <div className="mb-5 flex h-14 w-14 items-center justify-center rounded-xl border border-amber-400/30 bg-amber-400/10">
            <ShieldAlert className="h-7 w-7 text-amber-300" />
          </div>
          <h1 className="text-2xl font-bold text-slate-100 md:text-3xl">Évaluations actives désactivées</h1>
          <p className="mt-4 max-w-3xl text-sm leading-7 text-slate-300">
            AfricaWatch privilégie désormais une posture défensive : la plateforme reçoit des rapports provenant
            d’outils d’évaluation autorisés, les normalise, les corrèle à l’inventaire d’actifs et aide les équipes
            à prioriser la remédiation. Cette interface ne lance pas de reconnaissance réseau ni de scan.
          </p>
          <div className="mt-6 rounded-xl border border-amber-500/20 bg-amber-500/5 p-4 text-sm leading-6 text-amber-100/80">
            Les anciens endpoints d’évaluation sont bloqués par la politique serveur par défaut. Ne réactivez pas
            les évaluations actives en production. Pour un laboratoire isolé, toute exception doit être revue,
            documentée et autorisée par le responsable sécurité.
          </div>
          <div className="mt-7 grid gap-3 md:grid-cols-2">
            <Link href="/report-ingestion" className="group flex items-center justify-between gap-4 rounded-xl border border-cyan-700/50 bg-cyan-950/30 p-5 transition hover:border-cyan-400">
              <span className="flex items-center gap-3"><FileSearch className="h-5 w-5 text-cyan-300" /><span><b className="block text-sm text-slate-100">Importer des rapports</b><small className="mt-1 block text-xs text-slate-400">Nmap, Nuclei, Nessus et Shodan, sans lancer de scan.</small></span></span>
              <ArrowRight className="h-4 w-4 text-cyan-300 transition group-hover:translate-x-1" />
            </Link>
            <Link href="/vulns" className="group flex items-center justify-between gap-4 rounded-xl border border-slate-700 bg-slate-950/50 p-5 transition hover:border-emerald-500/50">
              <span className="flex items-center gap-3"><Workflow className="h-5 w-5 text-emerald-300" /><span><b className="block text-sm text-slate-100">Gérer les vulnérabilités</b><small className="mt-1 block text-xs text-slate-400">Examiner les constats et suivre la remédiation.</small></span></span>
              <ArrowRight className="h-4 w-4 text-emerald-300 transition group-hover:translate-x-1" />
            </Link>
          </div>
        </section>
      </main>
    </AppLayout>
  );
}
