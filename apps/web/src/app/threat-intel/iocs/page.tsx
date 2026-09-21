"use client";
import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Database, Search, RefreshCw } from "lucide-react";
import { api } from "@/lib/api";
import { cn, SEV, IOC_COLORS } from "@/lib/utils";
import AppLayout from "@/components/layout/Sidebar";

export default function IOCsPage() {
  const [iocs,setIocs]=useState<any[]>([]);
  const [stats,setStats]=useState<any>(null);
  const [loading,setLoading]=useState(true);
  const [search,setSearch]=useState("");
  const [severity,setSeverity]=useState("");
  const [african,setAfrican]=useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const p:any={page_size:50,ordering:"-last_seen"};
      if(search) p.search=search; if(severity) p.severity=severity; if(african) p.is_african_threat=true;
      const {data}=await api.iocs.list(p);
      setIocs(data.results||data);
    } catch {} finally { setLoading(false); }
  };

  useEffect(()=>{ load(); api.iocs.stats().then(({data})=>setStats(data)).catch(()=>{}); },[search,severity,african]);

  return (
    <AppLayout>
      <div className="p-4 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Database className="w-5 h-5 text-cyan-400"/>
            <h1 className="text-base font-bold tracking-widest text-cyan-300">IOC DATABASE</h1>
          </div>
          <button onClick={load} className="text-cyan-600 hover:text-cyan-400 p-1.5 border border-cyan-900/40 rounded-sm"><RefreshCw className="w-3.5 h-3.5"/></button>
        </div>
        {stats&&(
          <div className="grid grid-cols-5 gap-2">
            {[{l:"TOTAL",v:stats.total,c:"cyan"},{l:"ACTIFS",v:stats.active,c:"green"},{l:"AFRICAINS",v:stats.african_threats,c:"yellow"},{l:"CRITIQUES",v:stats.critical,c:"red"},{l:"24H",v:stats.new_last_24h,c:"orange"}].map(s=>(
              <div key={s.l} className="bg-[#0a1628] border border-cyan-900/30 rounded-sm p-2.5 text-center">
                <div className={`text-lg font-bold text-${s.c}-400 tabular-nums`}>{s.v?.toLocaleString()}</div>
                <div className="text-[9px] text-gray-500 tracking-widest">{s.l}</div>
              </div>
            ))}
          </div>
        )}
        <div className="flex gap-2">
          <div className="flex-1 relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500"/>
            <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Rechercher IP, domaine, hash..."
              className="w-full bg-[#0a1628] border border-cyan-900/30 text-sm text-gray-300 pl-8 pr-3 py-2 rounded-sm focus:outline-none focus:border-cyan-700/50 font-mono placeholder:text-gray-600"/>
          </div>
          <select value={severity} onChange={e=>setSeverity(e.target.value)}
            className="bg-[#0a1628] border border-cyan-900/30 text-sm text-gray-300 px-3 py-2 rounded-sm focus:outline-none">
            <option value="">Toutes sévérités</option>
            {["critical","high","medium","low","info"].map(s=><option key={s} value={s}>{s.toUpperCase()}</option>)}
          </select>
          <button onClick={()=>setAfrican(!african)} className={cn("px-3 py-2 text-[10px] tracking-widest border rounded-sm transition-colors",african?"bg-yellow-400/10 border-yellow-400/40 text-yellow-400":"border-cyan-900/30 text-gray-500 hover:text-cyan-400")}>🌍 AFRIQUE</button>
        </div>
        <div className="bg-[#0a1628] border border-cyan-900/30 rounded-sm overflow-hidden">
          <table className="w-full text-[11px] font-mono">
            <thead>
              <tr className="border-b border-cyan-900/20 text-[9px] tracking-widest text-gray-500">
                <th className="text-left px-3 py-2">TYPE</th><th className="text-left px-3 py-2">VALEUR</th><th className="text-left px-3 py-2">SÉVÉRITÉ</th><th className="text-left px-3 py-2">CONFIANCE</th><th className="text-left px-3 py-2">PAYS</th><th className="text-left px-3 py-2">VU</th><th className="text-left px-3 py-2">FAMILLES</th>
              </tr>
            </thead>
            <tbody>
              {loading?<tr><td colSpan={7} className="text-center py-8 text-gray-500">Chargement...</td></tr>:
               iocs.length===0?<tr><td colSpan={7} className="text-center py-8 text-gray-500">Aucun IOC trouvé</td></tr>:
               iocs.map((ioc,i)=>(
                <motion.tr key={ioc.id} initial={{opacity:0}} animate={{opacity:1}} transition={{delay:i*0.02}} className="border-b border-cyan-900/10 hover:bg-cyan-900/10 cursor-pointer">
                  <td className={cn("px-3 py-2 font-bold",IOC_COLORS[ioc.ioc_type]||"text-gray-400")}>{ioc.ioc_type.toUpperCase()}</td>
                  <td className="px-3 py-2 text-gray-300 max-w-xs"><span className="truncate block">{ioc.value}</span></td>
                  <td className="px-3 py-2"><span className={cn("px-1.5 py-0.5 border rounded-sm text-[9px] font-bold",SEV[ioc.severity]?.text,SEV[ioc.severity]?.bg,SEV[ioc.severity]?.border)}>{ioc.severity?.toUpperCase()}</span></td>
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-1.5">
                      <div className="w-16 bg-gray-800 rounded-full h-1"><div className="bg-cyan-500 h-1 rounded-full" style={{width:`${ioc.confidence}%`}}/></div>
                      <span className="text-gray-500">{ioc.confidence}%</span>
                    </div>
                  </td>
                  <td className="px-3 py-2 text-gray-400">{ioc.country_code||"—"}</td>
                  <td className="px-3 py-2 text-gray-500">{new Date(ioc.last_seen).toLocaleDateString("fr-FR")}</td>
                  <td className="px-3 py-2 text-gray-500">{ioc.malware_families?.slice(0,2).join(", ")||"—"}</td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </AppLayout>
  );
}
