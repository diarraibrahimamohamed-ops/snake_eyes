"use client";
import { useState } from "react";

export interface CountryThreat {
  country_code: string; country_name: string; total: number;
  critical: number; high: number; medium: number; low: number;
}
const CENTROIDS: Record<string,[number,number]> = {
  ML:[17,-3.9],MLI:[17,-3.9],NG:[9.1,8.7],NGA:[9.1,8.7],SN:[14.4,-14.5],SEN:[14.4,-14.5],
  GH:[7.9,-1.2],GHA:[7.9,-1.2],BF:[12.3,-1.6],BFA:[12.3,-1.6],CI:[7.5,-5.5],CIV:[7.5,-5.5],
  NE:[17.6,8.1],NER:[17.6,8.1],TG:[8.6,0.8],TGO:[8.6,0.8],BJ:[9.5,2.3],BEN:[9.5,2.3],
  CM:[5.7,12.7],CMR:[5.7,12.7],TD:[15.4,18.7],TCD:[15.4,18.7],MR:[20.3,-10.5],MRT:[20.3,-10.5],
  GN:[10.4,-10.8],GIN:[10.4,-10.8],GW:[12,-15],GNB:[12,-15],GM:[13.4,-15.4],GMB:[13.4,-15.4],
  LR:[6.5,-9.4],LBR:[6.5,-9.4],SL:[8.5,-11.8],SLE:[8.5,-11.8],GA:[-0.6,11.8],GAB:[-0.6,11.8],
  CG:[-0.7,15.2],COG:[-0.7,15.2],CD:[-2.8,23.7],COD:[-2.8,23.7],CF:[6.6,20.9],CAF:[6.6,20.9],
  AO:[-12.5,18.5],AGO:[-12.5,18.5],ZA:[-29,24],ZAF:[-29,24],KE:[0.2,37.9],KEN:[0.2,37.9],
  UG:[1.3,32.3],UGA:[1.3,32.3],TZ:[-6.3,35.4],TZA:[-6.3,35.4],RW:[-1.9,29.9],RWA:[-1.9,29.9],
  ET:[9.1,40.5],ETH:[9.1,40.5],SO:[5.2,46.2],SOM:[5.2,46.2],SD:[13.5,30.2],SDN:[13.5,30.2],
  SS:[7.3,30.3],SSD:[7.3,30.3],EG:[26.8,30.8],EGY:[26.8,30.8],LY:[26.3,17.2],LBY:[26.3,17.2],
  TN:[34,9.5],TUN:[34,9.5],DZ:[28,3],DZA:[28,3],MA:[31.8,-7.1],MAR:[31.8,-7.1],
  ZM:[-13.1,27.8],ZMB:[-13.1,27.8],ZW:[-19,29.9],ZWE:[-19,29.9],MZ:[-18.7,35.5],MOZ:[-18.7,35.5],
  NA:[-22.1,17.2],NAM:[-22.1,17.2],BW:[-22,24],BWA:[-22,24],LS:[-29.6,28.2],LSO:[-29.6,28.2],
  SZ:[-26.5,31.5],SWZ:[-26.5,31.5],MG:[-19,46.7],MDG:[-19,46.7],MW:[-13.3,34.3],MWI:[-13.3,34.3],
  BI:[-3.4,29.9],BDI:[-3.4,29.9],ER:[15.2,39.1],ERI:[15.2,39.1],DJ:[11.8,42.6],DJI:[11.8,42.6],
  GQ:[1.6,10.3],GNQ:[1.6,10.3],CV:[15.1,-23.6],CPV:[15.1,-23.6],KM:[-11.7,43.3],COM:[-11.7,43.3],
  ST:[0.2,6.6],STP:[0.2,6.6],SC:[-4.6,55.5],SYC:[-4.6,55.5],MU:[-20.2,57.5],MUS:[-20.2,57.5],
};
const COLORS = {critical:"#ef4444",high:"#f97316",medium:"#eab308",low:"#22c55e"};
const project = (lat:number,lng:number) => ({x:12+((lng+20)/80)*556,y:12+((38-lat)/76)*396});
const markerColor = (c:CountryThreat) => c.critical>0?COLORS.critical:c.high>0?COLORS.high:c.medium>0?COLORS.medium:COLORS.low;

export function ThreatMap({countries=[],unavailable=false}:{countries?:CountryThreat[];unavailable?:boolean}) {
  const [selected,setSelected] = useState<string|null>(null);
  const plotted = countries.map(c=>({...c,center:CENTROIDS[(c.country_code||"").toUpperCase()]})).filter(c=>Boolean(c.center));
  const active = plotted.find(c=>c.country_code===selected);
  const total = countries.reduce((sum,c)=>sum+c.total,0);
  return <div className="relative flex h-full min-h-[300px] flex-col">
    <div className="mb-2 flex justify-between text-[9px] font-mono text-gray-400"><span>{total.toLocaleString("fr-FR")} IOC · {countries.length} pays</span><span className="text-cyan-700">Agrégation nationale</span></div>
    {unavailable&&countries.length>0&&<div role="status" className="mb-1 text-[9px] text-amber-300">Actualisation échouée — affichage des dernières données connues.</div>}
    <div className="relative min-h-0 flex-1">
      <svg viewBox="0 0 580 420" className="h-full w-full" role="img" aria-label="Carte des menaces agrégées par pays">
        <defs><pattern id="aw-grid" width="36" height="36" patternUnits="userSpaceOnUse"><path d="M36 0H0V36" fill="none" stroke="rgba(0,229,255,.07)" strokeWidth=".6"/></pattern></defs>
        <rect width="580" height="420" fill="url(#aw-grid)"/><text x="290" y="210" textAnchor="middle" fill="rgba(0,229,255,.035)" fontSize="118" fontWeight="900">AFRIQUE</text>
        {plotted.map(c=>{
          const p=project(c.center![0],c.center![1]),r=Math.min(15,4+Math.log2(c.total+1)*1.4),color=markerColor(c),isActive=selected===c.country_code;
          return <g key={c.country_code} role="button" tabIndex={0} aria-label={c.country_name+": "+c.total+" IOC"}
            onClick={()=>setSelected(isActive?null:c.country_code)}
            onKeyDown={e=>{if(e.key==="Enter"||e.key===" "){e.preventDefault();setSelected(isActive?null:c.country_code);}}} style={{cursor:"pointer"}}>
            <circle cx={p.x} cy={p.y} r={r+(isActive?5:2)} fill={color} opacity={isActive ? 0.2 : 0.1}/>
            <circle cx={p.x} cy={p.y} r={r} fill={color} stroke={isActive?"#fff":"#07101f"} strokeWidth={isActive?1.5:.8}/>
            <text x={p.x} y={p.y+3} textAnchor="middle" fill="#07101f" fontSize="8" fontWeight="900">{c.total>99?"99+":c.total}</text>
          </g>;
        })}
      </svg>
      {active&&<div className="absolute left-3 top-3 rounded border border-cyan-800 bg-[#07101f]/95 px-3 py-2 text-[10px] shadow-xl">
        <div className="mb-1 font-bold text-cyan-300">{active.country_name||active.country_code}</div><div className="text-gray-300">{active.total} IOC</div>
        <div className="mt-1 flex flex-wrap gap-x-2">{(["critical","high","medium","low"] as const).map(k=><span key={k} style={{color:COLORS[k]}}>{k}: {active[k]}</span>)}</div>
      </div>}
      {countries.length===0&&<div className="absolute inset-0 flex items-center justify-center bg-[#07101f]/35 px-5 text-center text-xs text-gray-500">{unavailable?"Carte indisponible : le service de données n’a pas répondu.":"Aucun IOC géolocalisé par pays dans les données accessibles."}</div>}
    </div>
    <div className="mt-2 flex flex-wrap gap-3 text-[9px] font-mono">{Object.entries(COLORS).map(([k,v])=><span key={k} className="flex items-center gap-1 text-gray-400"><i className="h-2 w-2 rounded-full" style={{backgroundColor:v}}/>{k}</span>)}{countries.length>plotted.length&&<span className="text-gray-600">{countries.length-plotted.length} codes pays sans centroïde</span>}</div>
    <p className="mt-1 text-[8px] leading-relaxed text-gray-600">Les points représentent des centroïdes nationaux et des volumes d’IOC ; ils n’indiquent ni une cible ni la position exacte d’un attaquant.</p>
  </div>;
}
