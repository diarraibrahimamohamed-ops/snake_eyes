"use client";
import { useState, useEffect } from "react";
import { Globe, ExternalLink } from "lucide-react";
import { api } from "@/lib/api";
import AppLayout from "@/components/layout/Sidebar";
const LF:Record<string,string>={fr:"🇫🇷",en:"🇬🇧",ar:"🇲🇦",sw:"🇰🇪",ha:"🇳🇬",bm:"🇲🇱"};
const SC:Record<string,string>={alarming:"text-red-400",negative:"text-orange-400",neutral:"text-gray-400",positive:"text-green-400"};
export default function OSINTPage() {
  const [events,setEvents]=useState<any[]>([]);
  const [stats,setStats]=useState<any>(null);
  const [loading,setLoading]=useState(true);
  useEffect(()=>{
    api.osint.events({is_threat_relevant:true,ordering:"-published_at",page_size:50}).then(({data})=>setEvents(data.results||data)).finally(()=>setLoading(false));
    api.osint.stats().then(({data})=>setStats(data)).catch(()=>{});
  },[]);
  return (
    <AppLayout>
      <div className="p-4 space-y-4">
        <div className="flex items-center gap-2"><Globe className="w-5 h-5 text-purple-400"/><h1 className="text-base font-bold tracking-widest text-cyan-300">OSINT ENGINE</h1></div>
        {stats&&<div className="grid grid-cols-4 gap-2">{[{l:"EVENTS 24H",v:stats.last_24h},{l:"MENACES",v:stats.threat_relevant},{l:"TOTAL",v:stats.total},{l:"SOURCES",v:stats.by_source_type?.length||0}].map(s=>(
          <div key={s.l} className="bg-[#0a1628] border border-cyan-900/30 rounded-sm p-2.5 text-center"><div className="text-lg font-bold text-purple-400 tabular-nums">{s.v}</div><div className="text-[9px] text-gray-500 tracking-widest">{s.l}</div></div>
        ))}</div>}
        <div className="space-y-2">
          {loading?<div className="text-center py-8 text-gray-500">Chargement...</div>:events.map((ev,i)=>(
            <div key={ev.id} className="bg-[#0a1628] border border-cyan-900/20 rounded-sm p-3">
              <div className="flex items-start justify-between gap-2">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1.5">
                    <span className="text-[10px] text-purple-400 font-bold">{ev.source_name}</span>
                    <span>{LF[ev.language_detected]||"🌐"}</span>
                    <span className={`text-[9px] ${SC[ev.sentiment]||"text-gray-400"}`}>{ev.sentiment?.toUpperCase()}</span>
                    <div className="flex items-center gap-1">
                      <div className="w-12 bg-gray-800 rounded-full h-1"><div className="bg-purple-500 h-1 rounded-full" style={{width:`${ev.threat_relevance_score*100}%`}}/></div>
                      <span className="text-[9px] text-gray-500">{Math.round(ev.threat_relevance_score*100)}%</span>
                    </div>
                  </div>
                  <p className="text-sm text-gray-300 leading-relaxed">{(ev.content_translated||ev.content)?.slice(0,200)}...</p>
                </div>
                {ev.url&&<a href={ev.url} target="_blank" rel="noopener noreferrer" className="text-gray-600 hover:text-cyan-400 shrink-0"><ExternalLink className="w-3.5 h-3.5"/></a>}
              </div>
            </div>
          ))}
        </div>
      </div>
    </AppLayout>
  );
}
