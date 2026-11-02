import { create } from "zustand";
export interface ThreatScore { score:number;level:"stable"|"elevated"|"critical"|string;iocs_24h?:number;computed_at?:string; }
interface DashboardState {
 threatScore:ThreatScore|null;alerts:any[];iocs:any[];stats:any;isConnected:boolean;
 setThreatScore:(score:ThreatScore|null)=>void;setAlerts:(alerts:any[])=>void;setIocs:(iocs:any[])=>void;
 addAlert:(alert:any)=>void;addIOC:(ioc:any)=>void;setConnected:(connected:boolean)=>void;setStats:(stats:any)=>void;
}
export const useDashboardStore=create<DashboardState>(set=>({
 threatScore:null,alerts:[],iocs:[],stats:null,isConnected:false,
 setThreatScore:threatScore=>set({threatScore}),setAlerts:alerts=>set({alerts}),setIocs:iocs=>set({iocs}),
 addAlert:alert=>set(state=>({alerts:[alert,...state.alerts.filter(item=>String(item.id)!==String(alert.id))].slice(0,100)})),
 addIOC:ioc=>set(state=>({iocs:[ioc,...state.iocs.filter(item=>String(item.id)!==String(ioc.id))].slice(0,200)})),
 setConnected:isConnected=>set({isConnected}),setStats:stats=>set({stats}),
}));
