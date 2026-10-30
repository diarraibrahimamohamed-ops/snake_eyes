"use client";
import { useCallback,useEffect,useState } from "react";
import api from "@/lib/api";
import { useDashboardStore } from "@/lib/stores/dashboard";
import type { CountryThreat } from "@/components/dashboard/ThreatMap";
import type { OSINTItem } from "@/components/dashboard";

type MapPayload={african_threats:CountryThreat[];total_countries:number;total_iocs?:number;computed_at:string};
export function useDashboardData() {
 const setStats=useDashboardStore(s=>s.setStats),setThreatScore=useDashboardStore(s=>s.setThreatScore);
 const setAlerts=useDashboardStore(s=>s.setAlerts),setIocs=useDashboardStore(s=>s.setIocs);
 const [mapData,setMapData]=useState<MapPayload>({african_threats:[],total_countries:0,total_iocs:0,computed_at:""});
 const [osintEvents,setOsintEvents]=useState<OSINTItem[]>([]);
 const [loading,setLoading]=useState(true),[unavailable,setUnavailable]=useState(false),[lastChecked,setLastChecked]=useState<string|null>(null);
 const reload=useCallback(async()=>{
  const [statsResult,activityResult,mapResult]=await Promise.allSettled([api.dashboard.stats(),api.dashboard.activity(),api.dashboard.threatMap()]);
  let failures=0;
  if(statsResult.status==="fulfilled"){const stats=statsResult.value.data;setStats(stats);setThreatScore(stats?.threat_score&&typeof stats.threat_score.score==="number"?stats.threat_score:null);}else failures++;
  if(activityResult.status==="fulfilled"){const data=activityResult.value.data;setAlerts(Array.isArray(data?.alerts)?data.alerts:[]);setIocs(Array.isArray(data?.iocs)?data.iocs:[]);setOsintEvents(Array.isArray(data?.osint_events)?data.osint_events:[]);}else failures++;
  if(mapResult.status==="fulfilled"){const data=mapResult.value.data;setMapData({african_threats:Array.isArray(data?.african_threats)?data.african_threats:[],total_countries:Number(data?.total_countries||0),total_iocs:Number(data?.total_iocs||0),computed_at:data?.computed_at||""});}else failures++;
  setUnavailable(failures===3);setLastChecked(new Date().toISOString());setLoading(false);
 },[setStats,setThreatScore,setAlerts,setIocs]);
 useEffect(()=>{void reload();const timer=window.setInterval(()=>void reload(),60_000);return()=>window.clearInterval(timer);},[reload]);
 return {mapData,osintEvents,loading,unavailable,lastChecked,reload};
}
