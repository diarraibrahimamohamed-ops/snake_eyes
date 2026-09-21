"use client";
import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { AlertTriangle, CheckCircle, ArrowUpRight, RefreshCw } from "lucide-react";
import { api } from "@/lib/api";
import { cn, SEV } from "@/lib/utils";
import AppLayout from "@/components/layout/Sidebar";

export default function AlertsPage() {
  const [alerts,setAlerts]=useState<any[]>([]);
  const [stats,setStats]=useState<any>(null);
  const [loading,setLoading]=useState(true);
  const [status,setStatus]=useState("new");
  const [sev,setSev]=useState("");

  const load=async()=>{ setLoading(true); try{ const p:any={ordering:"-created_at",page_size:50}; if(status) p.status=status; if(sev) p.severity=sev; const {data}=await api.alerts.list(p); setAlerts(data.results||data); } catch{} finally{setLoading(false);}};
  useEffect(()=>{ load(); api.alerts.stats().then(({data})=>setStats(data)).catch(()=>{}); },[status,sev]);
  const ack=async(id:string)=>{ await api.alerts.acknowledge(id); setAlerts(p=>p.map(a=>a.id===id?{...a,status:"acknowledged"}:a)); };
  const esc=async(id:string)=>{ await api.alerts.escalate(id,{incident_title:`Incident — ${id}`}); setAlerts(p=>p.map(a=>a.id===id?{...a,status:"escalated"}:a)); };

  return (
    <AppLayout>
      <div className="p-4 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2"><AlertTriangle className="w-5 h-5 text-orange-400"/><h1 className="text-base font-bold tracking-widest text-cyan-300">SOC ALERTS</h1>{stats&&<span className="text-[10px] text-orange-400 border border-orange-400/30 bg-orange-400/10 px-2 py-0.5 rounded-sm">{stats.open} OPEN</span>}</div>
          <button onClick={load} className="text-cyan-600 hover:text-cyan-400 p-1.5 border border-cyan-900/40 rounded-sm"><RefreshCw className="w-3.5 h-3.5"/></button>
        </div>
        {stats&&<div className="grid grid-cols-4 gap-2">{[{l:"OUVERTES",v:stats.open,c:"orange"},{l:"CRITIQUES",v:stats.critical,c:"red"},{l:"24H",v:stats.last_24h,c:"cyan"},{l:"FP RATE",v:`${stats.false_positive_rate}%`,c:"green"}].map(s=>(
          <div key={s.l} className="bg-[#0a1628] border border-cyan-900/30 rounded-sm p-2.5 text-center"><div className={`text-lg font-bold text-${s.c}-400 tabular-nums`}>{s.v}</div><div className="text-[9px] text-gray-500 tracking-widest">{s.l}</div></div>
        ))}</div>}
        <div className="flex gap-2">
          {["new","acknowledged","investigating","escalated"].map(s=>(
            <button key={s} onClick={()=>setStatus(s===status?"":s)} className={cn("px-3 py-1.5 text-[10px] tracking-widest border rounded-sm transition-colors",status===s?"bg-cyan-500/15 border-cyan-500/40 text-cyan-400":"border-cyan-900/30 text-gray-500 hover:text-cyan-400")}>{s.toUpperCase()}</button>
          ))}
          <select value={sev} onChange={e=>setSev(e.target.value)} className="bg-[#0a1628] border border-cyan-900/30 text-[11px] text-gray-300 px-3 py-1.5 rounded-sm">
            <option value="">Toutes</option>{["critical","high","medium","low"].map(s=><option key={s} value={s}>{s.toUpperCase()}</option>)}
          </select>
        </div>
        <div className="space-y-2">
          <AnimatePresence>
            {loading?<div className="text-center py-12 text-gray-500">Chargement...</div>:
             alerts.length===0?<div className="text-center py-12 text-gray-500">Aucune alerte</div>:
             alerts.map((alert,i)=>(
              <motion.div key={alert.id} initial={{opacity:0,x:-10}} animate={{opacity:1,x:0}} exit={{opacity:0}} transition={{delay:i*0.03}}
                className={cn("bg-[#0a1628] border border-cyan-900/20 border-l-2 rounded-sm p-3",alert.severity==="critical"?"border-l-red-500":alert.severity==="high"?"border-l-orange-500":alert.severity==="medium"?"border-l-yellow-500":"border-l-green-500")}>
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={cn("text-[9px] px-1.5 py-0.5 border rounded-sm font-bold",SEV[alert.severity]?.text,SEV[alert.severity]?.bg,SEV[alert.severity]?.border)}>{alert.severity?.toUpperCase()}</span>
                      <span className="text-[9px] text-gray-500">{alert.source?.toUpperCase()}</span>
                      {alert.src_ip&&<span className="text-[9px] text-cyan-600 font-mono">{alert.src_ip}</span>}
                    </div>
                    <p className="text-sm text-gray-200 font-mono">{alert.title}</p>
                    <p className="text-[10px] text-gray-500 mt-0.5">{new Date(alert.created_at).toLocaleString("fr-FR")}</p>
                  </div>
                  {alert.status==="new"&&(
                    <div className="flex gap-1.5 shrink-0">
                      <button onClick={()=>ack(alert.id)} className="text-[9px] text-green-400 border border-green-400/30 px-2 py-1 rounded-sm hover:bg-green-400/10 flex items-center gap-1"><CheckCircle className="w-3 h-3"/>ACK</button>
                      <button onClick={()=>esc(alert.id)} className="text-[9px] text-orange-400 border border-orange-400/30 px-2 py-1 rounded-sm hover:bg-orange-400/10 flex items-center gap-1"><ArrowUpRight className="w-3 h-3"/>ESC</button>
                    </div>
                  )}
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
        </div>
      </div>
    </AppLayout>
  );
}
