"use client";
import { useState, useEffect } from "react";
import { Bug } from "lucide-react";
import { api } from "@/lib/api";
import { cn, SEV } from "@/lib/utils";
import AppLayout from "@/components/layout/Sidebar";
export default function VulnsPage() {
  const [vulns,setVulns]=useState<any[]>([]);
  const [stats,setStats]=useState<any>(null);
  const [loading,setLoading]=useState(true);
  useEffect(()=>{ api.vulns.list({status:"open",ordering:"-cvss_score",page_size:50}).then(({data})=>setVulns(data.results||data)).finally(()=>setLoading(false)); api.vulns.stats().then(({data})=>setStats(data)).catch(()=>{}); },[]);
  const remediate=async(id:string)=>{ await api.vulns.remediate(id,"Corrigé via AfricaWatch"); setVulns(p=>p.filter(v=>v.id!==id)); };
  return (
    <AppLayout>
      <div className="p-4 space-y-4">
        <div className="flex items-center gap-2"><Bug className="w-5 h-5 text-yellow-400"/><h1 className="text-base font-bold tracking-widest text-cyan-300">VULNERABILITY MANAGEMENT</h1></div>
        {stats&&<div className="grid grid-cols-5 gap-2">{[{l:"OUVERTES",v:stats.open,c:"yellow"},{l:"CRITIQUES",v:stats.critical,c:"red"},{l:"EXPLOITABLES",v:stats.exploitable,c:"red"},{l:"CVSS MOY",v:stats.avg_cvss,c:"orange"},{l:"TOTAL",v:stats.total,c:"cyan"}].map(s=>(
          <div key={s.l} className="bg-[#0a1628] border border-cyan-900/30 rounded-sm p-2.5 text-center"><div className={`text-lg font-bold text-${s.c}-400 tabular-nums`}>{s.v}</div><div className="text-[9px] text-gray-500 tracking-widest">{s.l}</div></div>
        ))}</div>}
        <div className="bg-[#0a1628] border border-cyan-900/30 rounded-sm overflow-hidden">
          <table className="w-full text-[11px] font-mono">
            <thead><tr className="border-b border-cyan-900/20 text-[9px] tracking-widest text-gray-500">
              <th className="text-left px-3 py-2">CVE</th><th className="text-left px-3 py-2">TITRE</th><th className="text-left px-3 py-2">SÉVÉRITÉ</th><th className="text-left px-3 py-2">CVSS</th><th className="text-left px-3 py-2">ACTIF</th><th className="text-left px-3 py-2">EXPLOIT</th><th className="text-left px-3 py-2">ACTION</th>
            </tr></thead>
            <tbody>
              {loading?<tr><td colSpan={7} className="text-center py-8 text-gray-500">Chargement...</td></tr>:
               vulns.map(v=>(
                <tr key={v.id} className="border-b border-cyan-900/10 hover:bg-cyan-900/10">
                  <td className="px-3 py-2 text-cyan-500">{v.cve_id||"N/A"}</td>
                  <td className="px-3 py-2 text-gray-300 max-w-xs"><span className="truncate block">{v.title}</span></td>
                  <td className="px-3 py-2"><span className={cn("px-1.5 py-0.5 border rounded-sm text-[9px] font-bold",SEV[v.severity]?.text,SEV[v.severity]?.bg,SEV[v.severity]?.border)}>{v.severity?.toUpperCase()}</span></td>
                  <td className="px-3 py-2"><span className={v.cvss_score>=9?"text-red-400":v.cvss_score>=7?"text-orange-400":"text-yellow-400"}>{v.cvss_score?.toFixed(1)||"—"}</span></td>
                  <td className="px-3 py-2 text-gray-400 truncate max-w-[120px]">{v.asset_name}</td>
                  <td className="px-3 py-2">{v.is_exploitable?<span className="text-red-400 font-bold">OUI</span>:<span className="text-gray-500">Non</span>}</td>
                  <td className="px-3 py-2"><button onClick={()=>remediate(v.id)} className="text-[9px] text-green-400 border border-green-400/30 px-2 py-0.5 rounded-sm hover:bg-green-400/10">CORRIGER</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </AppLayout>
  );
}
