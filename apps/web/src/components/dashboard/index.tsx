"use client";
import { motion } from "framer-motion";
import { AlertTriangle,Cpu,Database,Eye,Globe,Shield } from "lucide-react";
import { cn } from "@/lib/utils";

export type DashboardStats={
  threat_intelligence?:{total_iocs?:number;new_24h?:number;african_threats?:number};
  soc?:{alerts_open?:number;alerts_24h?:number;incidents_active?:number};
  osint?:{events_24h?:number};vulnerabilities?:{open?:number};infrastructure?:{assets?:number};
  threat_score?:{score?:number;level?:string;iocs_24h?:number}|null;
};
export type AlertItem={id:string;title:string;severity:string;status:string;source?:string;created_at?:string};
export type IOCItem={id:string;ioc_type:string;value:string;severity:string;country_code?:string;created_at?:string};
export type OSINTItem={id:string;content:string;source__name?:string;created_at?:string};
export type ActivityItem={id:string;category:string;title:string;detail:string;created_at?:string;severity?:string};
const fmt=(v?:number)=>typeof v==="number"?v.toLocaleString("fr-FR"):"—";
const when=(v?:string)=>{if(!v)return "date inconnue";const d=new Date(v);return Number.isNaN(d.getTime())?"date inconnue":d.toLocaleString("fr-FR",{day:"2-digit",month:"2-digit",hour:"2-digit",minute:"2-digit"});};
const COLORS:Record<string,string>={cyan:"text-cyan-400",orange:"text-orange-400",red:"text-red-400",purple:"text-purple-400",green:"text-green-400",yellow:"text-yellow-400"};
const SEVERITY:Record<string,string>={critical:"border-red-400/30 bg-red-400/10 text-red-400",high:"border-orange-400/30 bg-orange-400/10 text-orange-400",medium:"border-yellow-400/30 bg-yellow-400/10 text-yellow-400",low:"border-green-400/30 bg-green-400/10 text-green-400"};
const Empty=({message}:{message:string})=><div className="flex h-full min-h-[60px] items-center justify-center px-2 text-center text-[10px] text-gray-600">{message}</div>;

export function ThreatTicker({stats}:{stats:DashboardStats|null}) {
 const entries=[["IOCs / 24H",metric(stats?.threat_intelligence?.new_24h),"text-cyan-400"],["ALERTES OUVERTES",metric(stats?.soc?.alerts_open),"text-orange-400"],["INCIDENTS ACTIFS",metric(stats?.soc?.incidents_active),"text-red-400"],["MENACES AFRIQUE",metric(stats?.threat_intelligence?.african_threats),"text-yellow-400"]];
 return <div className="mx-6 flex-1 overflow-hidden"><div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[10px] font-mono"><b className="shrink-0 tracking-widest text-cyan-600">INDICATEURS :</b>{entries.map(e=><span key={e[0]} className="flex shrink-0 items-center gap-1"><b className={cn("tabular-nums",e[2])}>{e[1]}</b><span className="text-gray-500">{e[0]}</span></span>)}</div></div>;
}
export function StatsGrid({stats,loading,unavailable=false}:{stats:DashboardStats|null;loading:boolean;unavailable?:boolean}) {
 const metric=(value?:number)=>unavailable&&typeof value!=="number"?"N/D":fmt(value);
 const data=[
  ["IOCs ACTIFS",metric(stats?.threat_intelligence?.total_iocs),metric(stats?.threat_intelligence?.new_24h)+" nouveaux / 24h",Database,"cyan"],
  ["ALERTES OUVERTES",metric(stats?.soc?.alerts_open),metric(stats?.soc?.alerts_24h)+" créées / 24h",AlertTriangle,"orange"],
  ["INCIDENTS ACTIFS",metric(stats?.soc?.incidents_active),"Ouverts ou en investigation",Shield,"red"],
  ["ACTIFS INVENTORIÉS",metric(stats?.infrastructure?.assets),"Actifs actifs du périmètre",Eye,"purple"],
  ["ÉVÉNEMENTS OSINT / 24H",metric(stats?.osint?.events_24h),"Événements récents collectés",Globe,"green"],
  ["VULNÉRABILITÉS OUVERTES",metric(stats?.vulnerabilities?.open),"Constats encore ouverts",Cpu,"yellow"],
 ] as const;
 return <div className="grid grid-cols-2 border-b border-cyan-900/30 md:grid-cols-3 xl:grid-cols-6">{data.map((item,i)=>{const Icon=item[3];return <motion.div key={item[0]} initial={{opacity:0}} animate={{opacity:1}} transition={{delay:i*.04}} className="flex min-h-[76px] items-center justify-between border-r border-cyan-900/20 bg-[#07101f]/60 px-4 py-2.5">
  <div className="min-w-0"><div className="mb-0.5 truncate text-[9px] tracking-widest text-gray-500">{item[0]}</div><div className={cn("text-lg font-bold tabular-nums",COLORS[item[4]])}>{loading&&!stats?"…":item[1]}</div><div className="mt-0.5 truncate text-[8px] text-gray-600">{item[2]}</div></div><Icon className={cn("ml-2 h-4 w-4 shrink-0",COLORS[item[4]])}/>
 </motion.div>;})}</div>;
}
export function ThreatScoreGauge({score,level}:{score:number|null;level:string}) {
 const colors:Record<string,string>={stable:"#22c55e",elevated:"#f97316",critical:"#ef4444"},valid=typeof score==="number"&&Number.isFinite(score),value=valid?Math.max(0,Math.min(100,score)):0,r=58,circ=Math.PI*r,color=colors[level]||"#64748b";
 return <div className="flex h-full flex-col items-center justify-center gap-2"><svg width="140" height="78" viewBox="0 0 140 78" role="img" aria-label={valid?"Score de menace "+value+" sur 100":"Score non disponible"}>
  <path d={"M 12 74 A "+r+" "+r+" 0 0 1 128 74"} fill="none" stroke="rgba(255,255,255,.05)" strokeWidth="12" strokeLinecap="round"/>{valid&&<motion.path d={"M 12 74 A "+r+" "+r+" 0 0 1 128 74"} fill="none" stroke={color} strokeWidth="12" strokeLinecap="round" strokeDasharray={circ} initial={{strokeDashoffset:circ}} animate={{strokeDashoffset:circ-(value/100)*circ}} transition={{duration:1.1,ease:"easeOut"}}/>}
  <text x="70" y="60" textAnchor="middle" fill={valid?color:"#64748b"} fontSize="25" fontWeight="900">{valid?value:"N/D"}</text><text x="70" y="73" textAnchor="middle" fill="rgba(255,255,255,.3)" fontSize="9">/100</text>
 </svg><span className="rounded-sm border border-cyan-900/40 px-3 py-1 text-[10px] font-bold tracking-[.2em] text-gray-400">{valid?level.toUpperCase():"NON CALCULÉ"}</span><span className="text-center text-[9px] text-gray-500">Score de menace régional</span></div>;
}
export function LiveAlertFeed({alerts=[],unavailable=false}:{alerts?:AlertItem[];unavailable?:boolean}) {
 if(!alerts.length)return <Empty message={unavailable?"Service indisponible : impossible de vérifier les alertes.":"Aucune alerte récente dans le périmètre accessible."}/>;
 return <div className="h-full space-y-1.5 overflow-auto">{alerts.slice(0,8).map((a,i)=><motion.div key={a.id} initial={{opacity:0,x:8}} animate={{opacity:1,x:0}} transition={{delay:i*.03}} className="flex items-center gap-2 rounded-sm px-1 py-1 text-[9px] font-mono hover:bg-cyan-900/10">
  <span className={cn("shrink-0 rounded-sm border px-1 py-0.5 font-bold",SEVERITY[a.severity]||"border-slate-700 text-slate-400")}>{(a.severity||"info").slice(0,4).toUpperCase()}</span><span className="min-w-0 flex-1 truncate text-gray-300">{a.title}</span><span className="shrink-0 text-gray-600">{when(a.created_at)}</span>
 </motion.div>)}</div>;
}
const IOC_COLORS:Record<string,string>={ip:"text-cyan-400",ip_range:"text-cyan-400",domain:"text-orange-400",url:"text-red-400",md5:"text-purple-400",sha1:"text-purple-400",sha256:"text-purple-400",cve:"text-red-500"};
export function IOCStream({iocs=[],unavailable=false}:{iocs?:IOCItem[];unavailable?:boolean}) {
 if(!iocs.length)return <Empty message={unavailable?"Service indisponible : impossible de vérifier les IOC.":"Aucun IOC récent dans le périmètre accessible."}/>;
 return <div className="h-full space-y-1 overflow-auto">{iocs.slice(0,10).map(i=><div key={i.id} className="flex items-center gap-1.5 rounded-sm px-1 py-1 text-[9px] font-mono hover:bg-cyan-900/10">
  <span className={cn("w-12 shrink-0 font-bold",IOC_COLORS[i.ioc_type]||"text-gray-400")}>{(i.ioc_type||"IOC").toUpperCase()}</span><span title={i.value} className="min-w-0 flex-1 truncate text-gray-400">{i.value}</span>{i.country_code&&<span className="shrink-0 border border-cyan-900/50 px-1 text-cyan-600">{i.country_code}</span>}<span className={cn("shrink-0",(SEVERITY[i.severity]||"text-gray-500").split(" ").pop())}>●</span>
 </div>)}</div>;
}
export function OSINTProbe({items=[],unavailable=false}:{items?:OSINTItem[];unavailable?:boolean}) {
 if(!items.length)return <Empty message={unavailable?"Service indisponible : impossible de vérifier les observations OSINT.":"Aucun événement OSINT récent à afficher."}/>;
 return <div className="h-full space-y-2 overflow-auto">{items.slice(0,5).map((o,i)=><motion.div key={o.id} initial={{opacity:0,y:4}} animate={{opacity:1,y:0}} transition={{delay:i*.04}} className="rounded-sm border border-cyan-900/20 p-1.5">
  <div className="mb-1 flex items-center justify-between gap-2"><b className="truncate text-cyan-500">{o.source__name||"Source non renseignée"}</b><span className="shrink-0 text-gray-600">{when(o.created_at)}</span></div><p className="line-clamp-3 text-gray-300">{o.content}</p>
 </motion.div>)}</div>;
}
export function SystemLogs({items=[],unavailable=false}:{items?:ActivityItem[];unavailable?:boolean}) {
 if(!items.length)return <Empty message={unavailable?"Service indisponible : impossible de vérifier l’activité récente.":"Aucune activité récente enregistrée."}/>;
 const colors:Record<string,string>={ALERT:"text-orange-400",IOC:"text-cyan-400",OSINT:"text-purple-400"};
 return <div className="h-full space-y-1 overflow-auto">{items.slice(0,8).map(o=><div key={o.id} className="flex items-start gap-2 text-[9px] font-mono">
  <span className="shrink-0 tabular-nums text-gray-600">{when(o.created_at)}</span><span className={cn("w-12 shrink-0 font-bold",colors[o.category]||"text-gray-400")}>[{o.category}]</span><span className="min-w-0 truncate text-gray-300">{o.title}</span><span className="min-w-0 flex-1 truncate text-gray-500">{o.detail}</span>
 </div>)}</div>;
}
