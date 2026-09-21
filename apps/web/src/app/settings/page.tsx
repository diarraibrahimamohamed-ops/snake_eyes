"use client";
import { Settings, Key, Bell, Shield } from "lucide-react";
import { useAuthStore } from "@/lib/stores/auth";
import AppLayout from "@/components/layout/Sidebar";
export default function SettingsPage() {
  const { user } = useAuthStore();
  return (
    <AppLayout>
      <div className="p-4 space-y-4 max-w-2xl">
        <div className="flex items-center gap-2"><Settings className="w-5 h-5 text-gray-400"/><h1 className="text-base font-bold tracking-widest text-cyan-300">PARAMÈTRES</h1></div>
        <div className="bg-[#0a1628] border border-cyan-900/30 rounded-sm p-4">
          <h2 className="text-[10px] tracking-widest text-cyan-500 mb-3">PROFIL</h2>
          <div className="space-y-2 text-[11px]">
            {[{l:"Email",v:user?.email},{l:"Rôle",v:user?.role?.toUpperCase(),cls:"text-cyan-400 font-bold"},{l:"Organisation",v:user?.organization_name||"—"}].map(f=>(
              <div key={f.l} className="flex justify-between"><span className="text-gray-500">{f.l}</span><span className={f.cls||"text-gray-300 font-mono"}>{f.v}</span></div>
            ))}
          </div>
        </div>
        <div className="bg-[#0a1628] border border-cyan-900/30 rounded-sm p-4">
          <div className="flex items-center gap-2 mb-3"><Bell className="w-3.5 h-3.5 text-cyan-500"/><h2 className="text-[10px] tracking-widest text-cyan-500">NOTIFICATIONS</h2></div>
          {["Alertes critiques par email","Nouveaux IOCs africains","Incidents ouverts"].map(n=>(
            <label key={n} className="flex items-center justify-between py-1.5 cursor-pointer">
              <span className="text-[11px] text-gray-400">{n}</span>
              <div className="w-8 h-4 bg-cyan-500/20 border border-cyan-500/30 rounded-full relative"><div className="absolute right-0.5 top-0.5 w-3 h-3 bg-cyan-400 rounded-full"/></div>
            </label>
          ))}
        </div>
        <div className="bg-[#0a1628] border border-cyan-900/30 rounded-sm p-4">
          <div className="flex items-center gap-2 mb-3"><Key className="w-3.5 h-3.5 text-cyan-500"/><h2 className="text-[10px] tracking-widest text-cyan-500">CLÉ API</h2></div>
          <div className="flex items-center gap-2">
            <div className="flex-1 bg-[#060d1a] border border-cyan-900/30 px-3 py-2 rounded-sm font-mono text-[11px] text-gray-500">{"•".repeat(32)}</div>
            <button className="text-[10px] text-cyan-400 border border-cyan-500/30 px-3 py-2 rounded-sm hover:bg-cyan-500/10">Afficher</button>
            <button className="text-[10px] text-orange-400 border border-orange-400/30 px-3 py-2 rounded-sm hover:bg-orange-400/10">Régénérer</button>
          </div>
        </div>
      </div>
    </AppLayout>
  );
}
