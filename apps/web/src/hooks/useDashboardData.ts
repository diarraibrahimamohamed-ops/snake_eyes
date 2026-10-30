"use client";
import { useCallback,useEffect,useRef,useState } from "react";
import api from "@/lib/api";
import { useDashboardStore } from "@/lib/stores/dashboard";
import type { CountryThreat } from "@/components/dashboard/ThreatMap";
import type { OSINTItem } from "@/components/dashboard";

type MapPayload={african_threats:CountryThreat[];total_countries:number;total_iocs:number;computed_at:string};
type ResourceName="stats"|"activity"|"map";
type ResourceStatus="loading"|"ready"|"error";
type ResourceStates=Record<ResourceName,ResourceStatus>;
type SuccessTimestamps=Record<ResourceName,string|null>;

const initialStatuses:ResourceStates={stats:"loading",activity:"loading",map:"loading"};
const initialSuccess:SuccessTimestamps={stats:null,activity:null,map:null};

export function useDashboardData() {
 const setStats=useDashboardStore(s=>s.setStats),setThreatScore=useDashboardStore(s=>s.setThreatScore);
 const setAlerts=useDashboardStore(s=>s.setAlerts),setIocs=useDashboardStore(s=>s.setIocs);
 const [mapData,setMapData]=useState<MapPayload>({african_threats:[],total_countries:0,total_iocs:0,computed_at:""});
 const [osintEvents,setOsintEvents]=useState<OSINTItem[]>([]);
 const [loading,setLoading]=useState(true);
 const [resourceStatus,setResourceStatus]=useState<ResourceStates>(initialStatuses);
 const [lastSuccess,setLastSuccess]=useState<SuccessTimestamps>(initialSuccess);
 const [lastChecked,setLastChecked]=useState<string|null>(null);
 const inFlight=useRef(false);
 const mounted=useRef(false);

 const reload=useCallback(async()=>{
  if(inFlight.current)return;
  inFlight.current=true;
  if(mounted.current)setLoading(true);
  try {
   const [statsResult,activityResult,mapResult]=await Promise.allSettled([
    api.dashboard.stats(),api.dashboard.activity(),api.dashboard.threatMap()
   ]);
   const checkedAt=new Date().toISOString();
   const nextStatus:ResourceStates={stats:"error",activity:"error",map:"error"};
   const nextSuccess:SuccessTimestamps={stats:null,activity:null,map:null};

   if(statsResult.status==="fulfilled") {
    const stats=statsResult.value?.data;
    if(stats&&typeof stats==="object"&&stats.threat_intelligence&&stats.soc) {
     setStats(stats);
     setThreatScore(stats.threat_score&&typeof stats.threat_score.score==="number"?stats.threat_score:null);
     nextStatus.stats="ready";
     nextSuccess.stats=checkedAt;
    }
   }

   if(activityResult.status==="fulfilled") {
    const data=activityResult.value?.data;
    if(data&&Array.isArray(data.alerts)&&Array.isArray(data.iocs)&&Array.isArray(data.osint_events)) {
     setAlerts(data.alerts);
     setIocs(data.iocs);
     setOsintEvents(data.osint_events);
     nextStatus.activity="ready";
     nextSuccess.activity=checkedAt;
    }
   }

   if(mapResult.status==="fulfilled") {
    const data=mapResult.value?.data;
    if(data&&Array.isArray(data.african_threats)&&Number.isFinite(data.total_countries)) {
     setMapData({
      african_threats:data.african_threats,
      total_countries:Number(data.total_countries),
      total_iocs:Number.isFinite(data.total_iocs)?Number(data.total_iocs):0,
      computed_at:typeof data.computed_at==="string"?data.computed_at:""
     });
     nextStatus.map="ready";
     nextSuccess.map=checkedAt;
    }
   }

   if(mounted.current) {
    setResourceStatus(nextStatus);
    setLastSuccess(prev=>({
     stats:nextSuccess.stats||prev.stats,
     activity:nextSuccess.activity||prev.activity,
     map:nextSuccess.map||prev.map
    }));
    setLastChecked(checkedAt);
   }
  } finally {
   inFlight.current=false;
   if(mounted.current)setLoading(false);
  }
 },[setStats,setThreatScore,setAlerts,setIocs]);

 useEffect(()=>{
  mounted.current=true;
  void reload();
  const timer=window.setInterval(()=>void reload(),60_000);
  return ()=>{
   mounted.current=false;
   window.clearInterval(timer);
  };
 },[reload]);

 const unavailable=Object.values(resourceStatus).some(status=>status==="error");
 return {mapData,osintEvents,loading,unavailable,resourceStatus,lastChecked,lastSuccess,reload};
}
