"use client";
import { useEffect,useMemo,useState } from "react";
import { motion } from "framer-motion";
import { RefreshCw,Shield,Wifi,WifiOff } from "lucide-react";
import { ThreatMap } from "@/components/dashboard/ThreatMap";
import { ThreatTicker,StatsGrid,ThreatScoreGauge,LiveAlertFeed,IOCStream,OSINTProbe,SystemLogs,type ActivityItem } from "@/components/dashboard";
import { useDashboardStore } from "@/lib/stores/dashboard";
import { useDashboardData } from "@/hooks/useDashboardData";
import { useWebSocket } from "@/hooks/useWebSocket";
import { cn } from "@/lib/utils";

function Card({title,badge,badgeColor="cyan",children,className}:{title:string;badge?:string;badgeColor?:string;children:React.ReactNode;className?:string}) {
 const badges:Record<string,string>={red:"text-red-400 border-red-400/30 bg-red-400/10",cyan:"text-cyan-400 border-cyan-400/30 bg-cyan-400/10",orange:"text-orange-400 border-orange-400/30 bg-orange-400/10",purple:"text-purple-400 border-purple-400/30 bg-purple-400/10",green:"text-green-400 border-green-400/30 bg-green-400/10"};
 return <motion.section initial={{opacity:0,y:8}} animate={{opacity:1,y:0}} className={cn("relative flex flex-col rounded-sm border border-cyan-900/40 bg-[#0a1628]/80 transition-colors hover:border-cyan-700/50",className)}>
  {["top-0 left-0 border-t border-l","top-0 right-0 border-t border-r","bottom-0 left-0 border-b border-l","bottom-0 right-0 border-b border-r"].map((c,i)=><div key={i} className={cn("absolute h-3 w-3 border-cyan-500/50",c)}/>)}
  <div className="flex items-center justify-between border-b border-cyan-900/30 px-3 py-2"><span className="text-[11px] font-bold tracking-[0.15em] text-cyan-300">{title}</span>{badge&&<span className={cn("rounded-sm border px-2 py-0.5 text-[9px] font-bold tracking-widest",badges[badgeColor]||badges.cyan)}>{badge}</span>}</div>
  <div className="min-h-0 flex-1 overflow-hidden p-2">{children}</div>
 </motion.section>;
}
const clockLabel=(v:string|null)=>{if(!v)return "En attente des premières données";const d=new Date(v);return Number.isNaN(d.getTime())?"Date indisponible":d.toLocaleTimeString("fr-FR",{hour:"2-digit",minute:"2-digit",second:"2-digit"});};

export default function DashboardPage() {
 const {stats,threatScore,alerts,iocs,isConnected}=useDashboardStore();
 const {mapData,osintEvents,loading,unavailable,resourceStatus,lastChecked,lastSuccess,reload}=useDashboardData();
 const resourceLabels:Record<keyof typeof resourceStatus,string>={stats:"statistiques",activity:"activité et IOC",map:"carte"};
 const failedResources=(Object.entries(resourceStatus) as [keyof typeof resourceStatus,string][]).filter(([,status])=>status==="error").map(([name])=>resourceLabels[name]);
 const [clock,setClock]=useState("");
 useWebSocket();
 useEffect(()=>{const update=()=>setClock(new Date().toLocaleString("fr-FR",{dateStyle:"medium",timeStyle:"medium"}));update();const t=window.setInterval(update,1000);return()=>window.clearInterval(t);},[]);
 const activityItems=useMemo<ActivityItem[]>(()=>{
  const rows:ActivityItem[]=[
   ...alerts.map((a:any)=>({id:"alert-"+a.id,category:"ALERT",title:a.title||"Alerte",detail:[a.severity,a.source].filter(Boolean).join(" · "),created_at:a.created_at,severity:a.severity})),
   ...iocs.map((i:any)=>({id:"ioc-"+i.id,category:"IOC",title:"Indicateur "+String(i.ioc_type||"IOC").toUpperCase(),detail:i.value||"",created_at:i.created_at,severity:i.severity})),
   ...osintEvents.map((o:any)=>({id:"osint-"+o.id,category:"OSINT",title:o.source__name||"Événement OSINT",detail:o.content||"",created_at:o.created_at})),
  ];
  return rows.sort((a,b)=>(b.created_at?new Date(b.created_at).getTime():0)-(a.created_at?new Date(a.created_at).getTime():0)).slice(0,10);
 },[alerts,iocs,osintEvents]);
 const openAlerts=stats?.soc?.alerts_open??alerts.filter((a:any)=>a.status==="new").length;

 return <div className="min-h-screen overflow-hidden bg-[#060d1a] font-mono text-white">
  <header className="sticky top-0 z-50 border-b border-cyan-900/40 bg-[#07101f]/90 backdrop-blur-sm"><div className="flex flex-wrap items-center justify-between gap-3 px-5 py-3">
   <div className="flex items-center gap-3"><div className="relative"><Shield className="h-7 w-7 text-cyan-400"/><motion.div className="absolute inset-0 rounded-full border border-cyan-400/30" animate={{scale:[1,1.5],opacity:[.5,0]}} transition={{duration:2,repeat:Infinity}}/></div><div><h1 className="text-base font-bold tracking-[0.25em] text-cyan-400">AFRICAWATCH</h1><p className="text-[9px] tracking-widest text-cyan-600">CYBER INTELLIGENCE PLATFORM</p></div></div>
   <ThreatTicker stats={stats}/>
   <div className="flex items-center gap-3 text-[10px]"><div className="flex items-center gap-1.5">{isConnected?<><Wifi className="h-3.5 w-3.5 text-green-400"/><span className="text-green-400">STREAM LIVE</span></>:<><WifiOff className="h-3.5 w-3.5 text-gray-500"/><span className="text-gray-500">STREAM DÉCONNECTÉ</span></>}</div><span className="hidden text-[9px] tabular-nums text-cyan-700 lg:inline">{clock}</span><button type="button" onClick={()=>void reload()} disabled={loading} aria-label="Actualiser les données" className="rounded border border-cyan-900/50 p-2 text-cyan-500 hover:border-cyan-500 disabled:opacity-40"><RefreshCw className={cn("h-3.5 w-3.5",loading&&"animate-spin")}/></button></div>
  </div></header>
  {unavailable&&<div role="status" className="border-b border-amber-900/40 bg-amber-950/30 px-4 py-2 text-[10px] text-amber-300">Actualisation indisponible pour : {failedResources.join(", ")}. Les dernières données valides sont conservées ; un panneau vide ne sera pas présenté comme un résultat confirmé.</div>}
  <StatsGrid stats={stats} loading={loading} unavailable={resourceStatus.stats==="error"}/>
  <main className="grid grid-cols-1 gap-3 p-3 xl:grid-cols-12">
   <div className="xl:col-span-7 xl:row-span-2"><Card title="PAYS — INDICATEURS DE MENACE" badge={mapData.total_countries+" PAYS"} badgeColor="red" className="h-[480px]"><ThreatMap countries={mapData.african_threats} unavailable={resourceStatus.map==="error"}/></Card></div>
   <div className="xl:col-span-2"><Card title="SCORE DE MENACE" badge={threatScore?"CALCULÉ":"INDISPONIBLE"} className="h-[232px]"><ThreatScoreGauge score={threatScore?.score??null} level={threatScore?.level??"unknown"}/></Card></div>
   <div className="xl:col-span-3"><Card title="IOC RÉCENTS" badge={iocs.length+" ÉLÉMENTS"} className="h-[232px]"><IOCStream iocs={iocs} unavailable={resourceStatus.activity==="error"}/></Card></div>
   <div className="xl:col-span-2"><Card title="ALERTES RÉCENTES" badge={openAlerts+" OUVERTES"} badgeColor="orange" className="h-[234px]"><LiveAlertFeed alerts={alerts} unavailable={resourceStatus.activity==="error"}/></Card></div>
   <div className="xl:col-span-3"><Card title="OBSERVATIONS OSINT" badge={osintEvents.length+" ÉVÉNEMENTS"} badgeColor="purple" className="h-[234px]"><OSINTProbe items={osintEvents} unavailable={resourceStatus.activity==="error"}/></Card></div>
   <div className="xl:col-span-12"><Card title="ACTIVITÉ RÉCENTE" badge={activityItems.length+" ÉVÉNEMENTS"} badgeColor="green" className="h-[150px]"><SystemLogs items={activityItems} unavailable={resourceStatus.activity==="error"}/></Card></div>
  </main>
  <footer className="flex flex-wrap justify-between gap-2 px-4 pb-3 text-[9px] text-gray-600"><span>{loading?"Synchronisation des sources…":"Dernière tentative API : "+clockLabel(lastChecked)}</span><span className="hidden sm:inline">Dernières réponses réussies — stats : {clockLabel(lastSuccess.stats)} · activité : {clockLabel(lastSuccess.activity)} · carte : {clockLabel(lastSuccess.map)}</span><span>Les données affichées respectent le périmètre d’accès de la session.</span></footer>
 </div>;
}
