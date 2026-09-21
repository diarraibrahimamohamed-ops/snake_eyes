import { create } from "zustand";
interface ThreatScore { score:number; level:"stable"|"elevated"|"critical"; iocs_24h:number; computed_at:string; }
interface DashboardState { threatScore:ThreatScore; alerts:any[]; iocs:any[]; stats:any; isConnected:boolean; setThreatScore:(s:ThreatScore)=>void; addAlert:(a:any)=>void; addIOC:(i:any)=>void; setConnected:(v:boolean)=>void; setStats:(s:any)=>void; }
export const useDashboardStore = create<DashboardState>((set)=>({
  threatScore:{score:0,level:"stable",iocs_24h:0,computed_at:new Date().toISOString()},
  alerts:[], iocs:[], stats:null, isConnected:false,
  setThreatScore:(t)=>set({threatScore:t}),
  addAlert:(a)=>set(s=>({alerts:[a,...s.alerts].slice(0,100)})),
  addIOC:(i)=>set(s=>({iocs:[i,...s.iocs].slice(0,200)})),
  setConnected:(c)=>set({isConnected:c}),
  setStats:(stats)=>set({stats}),
}));
