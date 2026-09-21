"use client";
import { useState, useEffect } from "react";
import { Radio, Clock } from "lucide-react";
import { api } from "@/lib/api";
import { cn, SEV } from "@/lib/utils";
import AppLayout from "@/components/layout/Sidebar";
const SC:Record<string,string>={open:"text-red-400 bg-red-400/10 border-red-400/30",investigating:"text-orange-400 bg-orange-400/10 border-orange-400/30",contained:"text-yellow-400 bg-yellow-400/10 border-yellow-400/30",closed:"text-green-400 bg-green-400/10 border-green-400/30"};
export default function IncidentsPage() {
  const [incidents,setIncidents]=useState<any[]>([]);
  const [selected,setSelected]=useState<any>(null);
  const [loading,setLoading]=useState(true);
  useEffect(()=>{ api.incidents.list({ordering:"-detected_at",page_size:50}).then(({data})=>setIncidents(data.results||data)).finally(()=>setLoading(false)); },[]);
  const changeStatus=async(id:string,status:string)=>{ await api.incidents.changeStatus(id,status); setIncidents(p=>p.map(i=>i.id===id?{...i,status}:i)); if(selected?.id===id) setSelected((s:any)=>({...s,status})); };
  return (
    <AppLayout>
      <div className="p-4 space-y-4">
        <div className="flex items-center gap-2"><Radio className="w-5 h-5 text-red-400"/><h1 className="text-base font-bold tracking-widest text-cyan-300">INCIDENTS</h1></div>
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-2">
            {loading?<div className="text-center py-8 text-gray-500">Chargement...</div>:incidents.map(inc=>(
              <div key={inc.id} onClick={()=>setSelected(inc)} className={cn("bg-[#0a1628] border rounded-sm p-3 cursor-pointer transition-all",selected?.id===inc.id?"border-cyan-500/50":"border-cyan-900/20 hover:border-cyan-700/30")}>
                <div className="flex items-center justify-between mb-1">
                  <span className={cn("text-[9px] font-bold",SEV[inc.severity]?.text)}>{inc.severity?.toUpperCase()}</span>
                  <span className={cn("text-[9px] px-1.5 py-0.5 border rounded-sm",SC[inc.status]||"text-gray-400")}>{inc.status?.toUpperCase()}</span>
                </div>
                <p className="text-sm text-gray-200 font-mono leading-snug">{inc.title}</p>
                <div className="flex items-center gap-1.5 mt-1"><Clock className="w-3 h-3 text-gray-600"/><span className="text-[9px] text-gray-500">{new Date(inc.detected_at).toLocaleString("fr-FR")}</span></div>
              </div>
            ))}
          </div>
          {selected&&(
            <div className="bg-[#0a1628] border border-cyan-900/30 rounded-sm p-4 space-y-3">
              <h2 className="text-sm font-bold text-cyan-300">{selected.title}</h2>
              <p className="text-[11px] text-gray-400 leading-relaxed">{selected.description}</p>
              <div className="grid grid-cols-2 gap-2 text-[10px]">
                <div><span className="text-gray-500">Type:</span><span className="ml-1 text-gray-300">{selected.incident_type}</span></div>
                <div><span className="text-gray-500">Systèmes:</span><span className="ml-1 text-gray-300">{selected.systems_affected}</span></div>
                <div><span className="text-gray-500">Données:</span><span className={cn("ml-1",selected.data_compromised?"text-red-400":"text-green-400")}>{selected.data_compromised?"Compromises":"Intactes"}</span></div>
              </div>
              <div>
                <p className="text-[9px] text-gray-500 tracking-widest mb-2">CHANGER STATUT</p>
                <div className="flex flex-wrap gap-1.5">
                  {["investigating","contained","eradicated","recovered","closed"].map(s=>(
                    <button key={s} onClick={()=>changeStatus(selected.id,s)} disabled={selected.status===s} className={cn("text-[9px] px-2 py-1 border rounded-sm transition-colors",selected.status===s?"border-cyan-500/40 text-cyan-400 bg-cyan-500/10":"border-cyan-900/30 text-gray-500 hover:text-cyan-400")}>{s.toUpperCase()}</button>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </AppLayout>
  );
}
