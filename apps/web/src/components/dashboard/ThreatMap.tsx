"use client";
import { useEffect, useState } from "react";
import { motion } from "framer-motion";

const NODES = [
  {id:1,lat:12.3,lng:-1.5,country:"Burkina Faso",sev:"critical",label:"GOV-BF-01"},
  {id:2,lat:5.5,lng:-0.2,country:"Ghana",sev:"high",label:"BANK-GH-03"},
  {id:3,lat:14.7,lng:-17.4,country:"Sénégal",sev:"critical",label:"TELECOM-SN"},
  {id:4,lat:-1.3,lng:36.8,country:"Kenya",sev:"high",label:"MMONEY-KE"},
  {id:5,lat:6.4,lng:2.4,country:"Bénin",sev:"medium",label:"EDU-BJ-01"},
  {id:6,lat:-25.7,lng:28.2,country:"Afrique du Sud",sev:"critical",label:"FIN-ZA-07"},
  {id:7,lat:33.9,lng:9.6,country:"Tunisie",sev:"high",label:"GOV-TN-02"},
  {id:8,lat:9.0,lng:7.5,country:"Nigéria",sev:"critical",label:"BANK-NG-11"},
  {id:9,lat:12.1,lng:15.0,country:"Tchad",sev:"high",label:"GOV-TD-01"},
  {id:10,lat:30.0,lng:31.2,country:"Égypte",sev:"medium",label:"INFRA-EG"},
];
const COLORS:{[k:string]:string} = {critical:"#ef4444",high:"#f97316",medium:"#eab308",low:"#22c55e"};
const W=580, H=420;

function proj(lat:number,lng:number){
  const x=Math.max(10,Math.min(W-10,((lng-(-20))/75)*W));
  const y=Math.max(10,Math.min(H-10,((38-lat)/76)*H));
  return {x,y};
}

export function ThreatMap() {
  const [active,setActive]=useState<number|null>(null);
  const [lines,setLines]=useState<number[]>([]);
  useEffect(()=>{
    const iv=setInterval(()=>{ setLines(p=>[...p.slice(-4),NODES[Math.floor(Math.random()*NODES.length)].id]); },2000);
    return ()=>clearInterval(iv);
  },[]);

  return (
    <div className="relative w-full h-full">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-full">
        <defs>
          <filter id="glow"><feGaussianBlur stdDeviation="3" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
        </defs>
        {Array.from({length:10}).map((_,i)=>(
          <line key={`h${i}`} x1="0" y1={i*(H/9)} x2={W} y2={i*(H/9)} stroke="rgba(0,229,255,0.04)" strokeWidth="0.5"/>
        ))}
        {Array.from({length:14}).map((_,i)=>(
          <line key={`v${i}`} x1={i*(W/13)} y1="0" x2={i*(W/13)} y2={H} stroke="rgba(0,229,255,0.04)" strokeWidth="0.5"/>
        ))}
        <text x={W/2} y={H/2} textAnchor="middle" fill="rgba(0,229,255,0.03)" fontSize="160" fontWeight="900" dominantBaseline="middle">AFRICA</text>
        {NODES.map(node=>{
          const {x,y}=proj(node.lat,node.lng);
          const color=COLORS[node.sev]||"#gray";
          const size=node.sev==="critical"?6:node.sev==="high"?5:4;
          const isActive=active===node.id;
          return (
            <g key={node.id} onClick={()=>setActive(isActive?null:node.id)} style={{cursor:"pointer"}}>
              <motion.circle cx={x} cy={y} r={size+10} fill="none" stroke={color} strokeWidth="1"
                animate={{r:[size+4,size+18],opacity:[0.6,0]}} transition={{duration:node.sev==="critical"?1:2,repeat:Infinity,ease:"easeOut"}}/>
              <circle cx={x} cy={y} r={size} fill={color} filter="url(#glow)" opacity={0.9}/>
              <circle cx={x} cy={y} r={size*0.4} fill="white" opacity={0.9}/>
              <text x={x+size+4} y={y-3} fill={color} fontSize="7" fontFamily="monospace" fontWeight="bold">{node.label}</text>
              <text x={x+size+4} y={y+7} fill="rgba(255,255,255,0.35)" fontSize="6" fontFamily="monospace">{node.country}</text>
              {isActive&&(
                <g>
                  <rect x={x+10} y={y-28} width="120" height="38" fill="#0a1628" stroke={color} strokeWidth="0.8" rx="2"/>
                  <text x={x+15} y={y-12} fill={color} fontSize="8" fontWeight="bold">{node.sev.toUpperCase()} — {node.country}</text>
                  <text x={x+15} y={y+2} fill="rgba(255,255,255,0.5)" fontSize="7">Target: {node.label}</text>
                </g>
              )}
            </g>
          );
        })}
        <rect x="8" y="8" width="105" height="28" fill="rgba(0,0,0,0.6)" stroke="rgba(239,68,68,0.4)" strokeWidth="0.8" rx="2"/>
        <text x="14" y="19" fill="#ef4444" fontSize="7" fontWeight="bold" fontFamily="monospace">● CRITICAL THREATS</text>
        <text x="14" y="30" fill="rgba(255,255,255,0.4)" fontSize="7" fontFamily="monospace">{NODES.filter(n=>n.sev==="critical").length} active / Africa</text>
      </svg>
      <div className="absolute bottom-1 right-1 flex gap-2 text-[9px] font-mono">
        {Object.entries(COLORS).map(([s,c])=>(
          <div key={s} className="flex items-center gap-1">
            <div className="w-2 h-2 rounded-full" style={{backgroundColor:c}}/>
            <span className="text-gray-400">{s}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
