"use client";
import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { TrendingUp, TrendingDown, Minus, Shield, AlertTriangle, Eye, Cpu, Database, Globe } from "lucide-react";
import { cn } from "@/lib/utils";

const TICKER=[{l:"CRITICAL",v:"●",c:"text-red-400"},{l:"ELEVATED",v:"●",c:"text-orange-400"},{l:"STABLE",v:"●",c:"text-green-400"},{l:"IOCs/24H",v:"1,247",c:"text-cyan-400"},{l:"ALERTS",v:"38",c:"text-orange-400"},{l:"INCIDENTS",v:"7",c:"text-red-400"},{l:"FEEDS",v:"24",c:"text-green-400"},{l:"AF.THREATS",v:"89",c:"text-yellow-400"}];

export function ThreatTicker(){
  return (
    <div className="flex-1 mx-6 overflow-hidden">
      <div className="flex items-center gap-2 text-[10px] font-mono">
        <span className="text-cyan-600 tracking-widest shrink-0 font-bold">THREAT INDICATORS:</span>
        <motion.div className="flex gap-4 items-center" animate={{x:[0,-700]}} transition={{duration:18,repeat:Infinity,ease:"linear"}}>
          {[...TICKER,...TICKER].map((t,i)=>(
            <span key={i} className="flex items-center gap-1 shrink-0">
              <span className={cn("font-bold",t.c)}>{t.v}</span>
              <span className="text-gray-500">{t.l}</span>
              <span className="text-cyan-900 mx-1">|</span>
            </span>
          ))}
        </motion.div>
      </div>
    </div>
  );
}

const STATS=[
  {label:"IOCs ACTIFS",value:"48,291",trend:"+12%",up:true,icon:Database,color:"cyan"},
  {label:"ALERTES OPEN",value:"38",trend:"+3",up:true,icon:AlertTriangle,color:"orange"},
  {label:"INCIDENTS",value:"7",trend:"-2",up:false,icon:Shield,color:"red"},
  {label:"ACTIFS",value:"2,847",trend:"+156",up:true,icon:Eye,color:"purple"},
  {label:"SOURCES OSINT",value:"312",trend:"=",up:null,icon:Globe,color:"green"},
  {label:"SCORE AFRIQUE",value:"67/100",trend:"+8",up:true,icon:Cpu,color:"yellow"},
];
const CM:Record<string,string>={cyan:"text-cyan-400",orange:"text-orange-400",red:"text-red-400",purple:"text-purple-400",green:"text-green-400",yellow:"text-yellow-400"};

export function StatsGrid(){
  return (
    <div className="grid grid-cols-6 border-b border-cyan-900/30">
      {STATS.map((s,i)=>{const Icon=s.icon;return(
        <motion.div key={i} initial={{opacity:0}} animate={{opacity:1}} transition={{delay:i*0.05}}
          className="flex items-center justify-between px-4 py-2.5 bg-[#07101f]/60 border-r border-cyan-900/20 last:border-r-0">
          <div>
            <div className="text-[9px] text-gray-500 tracking-widest mb-0.5">{s.label}</div>
            <div className={cn("text-lg font-bold tabular-nums",CM[s.color])}>{s.value}</div>
          </div>
          <div className="flex flex-col items-end gap-1">
            <Icon className={cn("w-4 h-4",CM[s.color])}/>
            <span className={cn("text-[9px] font-bold flex items-center gap-0.5",s.up===true?"text-red-400":s.up===false?"text-green-400":"text-gray-500")}>
              {s.up===true?<TrendingUp className="w-2.5 h-2.5"/>:s.up===false?<TrendingDown className="w-2.5 h-2.5"/>:<Minus className="w-2.5 h-2.5"/>}
              {s.trend}
            </span>
          </div>
        </motion.div>
      );})}
    </div>
  );
}

export function ThreatScoreGauge({score=67,level="elevated"}:{score:number;level:string}){
  const colors:Record<string,string>={stable:"#22c55e",elevated:"#f97316",critical:"#ef4444"};
  const color=colors[level]||"#f97316";
  const r=58,circ=Math.PI*r,prog=(score/100)*circ;
  return (
    <div className="flex flex-col items-center justify-center h-full gap-2">
      <svg width="140" height="78" viewBox="0 0 140 78">
        <path d={`M 12 74 A ${r} ${r} 0 0 1 128 74`} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="12" strokeLinecap="round"/>
        <motion.path d={`M 12 74 A ${r} ${r} 0 0 1 128 74`} fill="none" stroke={color} strokeWidth="12" strokeLinecap="round"
          strokeDasharray={circ} initial={{strokeDashoffset:circ}} animate={{strokeDashoffset:circ-prog}}
          transition={{duration:1.5,ease:"easeOut"}} style={{filter:`drop-shadow(0 0 8px ${color})`}}/>
        <text x="70" y="60" textAnchor="middle" fill={color} fontSize="28" fontWeight="900" fontFamily="monospace">{score}</text>
        <text x="70" y="73" textAnchor="middle" fill="rgba(255,255,255,0.3)" fontSize="9" fontFamily="monospace">/100</text>
      </svg>
      <span className={cn("text-[10px] font-bold tracking-[0.2em] px-3 py-1 border rounded-sm",
        level==="critical"?"text-red-400 border-red-400/30 bg-red-400/10":level==="elevated"?"text-orange-400 border-orange-400/30 bg-orange-400/10":"text-green-400 border-green-400/30 bg-green-400/10")}>
        {level.toUpperCase()}
      </span>
      <span className="text-[9px] text-gray-500 text-center">Score menace Afrique</span>
    </div>
  );
}

const SAMPLE_ALERTS=[{id:"1",title:"Ransomware C2 detected",severity:"critical",source:"Suricata",time:"0m"},{id:"2",title:"Brute force SSH",severity:"high",source:"Wazuh",time:"2m"},{id:"3",title:"Phishing domain active",severity:"high",source:"OSINT",time:"5m"},{id:"4",title:"Port scan detected",severity:"medium",source:"Zeek",time:"8m"},{id:"5",title:"IOC match: known APT",severity:"critical",source:"TI",time:"12m"}];
const SB:Record<string,string>={critical:"text-red-400 bg-red-400/10 border-red-400/30",high:"text-orange-400 bg-orange-400/10 border-orange-400/30",medium:"text-yellow-400 bg-yellow-400/10 border-yellow-400/30",low:"text-green-400 bg-green-400/10 border-green-400/30"};

export function LiveAlertFeed({alerts=SAMPLE_ALERTS}:{alerts?:typeof SAMPLE_ALERTS}){
  return (
    <div className="space-y-1.5 h-full overflow-hidden">
      {alerts.map((a,i)=>(
        <motion.div key={a.id} initial={{opacity:0,x:10}} animate={{opacity:1,x:0}} transition={{delay:i*0.05}}
          className="flex items-center gap-2 text-[9px] font-mono hover:bg-cyan-900/10 px-1 py-0.5 rounded-sm cursor-pointer">
          <span className={cn("shrink-0 border px-1 py-0.5 rounded-sm font-bold tracking-wider",SB[a.severity])}>{a.severity.slice(0,4).toUpperCase()}</span>
          <span className="text-gray-300 truncate flex-1">{a.title}</span>
          <span className="text-cyan-600 shrink-0">{a.source}</span>
          <span className="text-gray-600 shrink-0">{a.time}</span>
        </motion.div>
      ))}
    </div>
  );
}

const SAMPLE_IOCS=[{type:"IP",value:"197.234.x.x",sev:"critical",cc:"NG"},{type:"MD5",value:"a3f9c84b...",sev:"high",cc:"—"},{type:"URL",value:"phish.mali-gov.tk",sev:"critical",cc:"ML"},{type:"IP",value:"41.206.x.x",sev:"high",cc:"GH"},{type:"SHA256",value:"7d4e21f9...",sev:"high",cc:"—"},{type:"DOMAIN",value:"c2-emotet.top",sev:"critical",cc:"—"},{type:"CVE",value:"CVE-2024-3094",sev:"critical",cc:"—"}];
const TC:Record<string,string>={IP:"text-cyan-400",MD5:"text-purple-400",URL:"text-red-400",DOMAIN:"text-orange-400",SHA256:"text-purple-500",CVE:"text-red-500"};

export function IOCStream({iocs=SAMPLE_IOCS}:{iocs?:typeof SAMPLE_IOCS}){
  return (
    <div className="space-y-1 h-full overflow-hidden">
      {iocs.map((ioc,i)=>(
        <motion.div key={i} initial={{opacity:0}} animate={{opacity:1}} transition={{delay:i*0.03}}
          className="flex items-center gap-1.5 text-[9px] font-mono hover:bg-cyan-900/10 px-1 rounded-sm">
          <span className={cn("font-bold w-10 shrink-0",TC[ioc.type]||"text-gray-400")}>{ioc.type}</span>
          <span className="text-gray-400 truncate flex-1">{ioc.value}</span>
          {ioc.cc!=="—"&&<span className="text-cyan-600 shrink-0 border border-cyan-900/50 px-1 rounded-sm">{ioc.cc}</span>}
          <span className={cn("font-bold shrink-0",ioc.sev==="critical"?"text-red-400":ioc.sev==="high"?"text-orange-400":"text-yellow-400")}>●</span>
        </motion.div>
      ))}
    </div>
  );
}

const OSINT_ITEMS=[{p:"Twitter/X",h:"@osint_africa",c:"BGP route hijack détecté AS37282 Mali Telecom",t:"1m"},{p:"Telegram",h:"CyberAfrica_FR",c:"Nouveau ransomware ciblant banques Ouest-Afrique",t:"4m"},{p:"DarkWeb",h:"BreachForum",c:"Database leak: 50k records .sn gov domain",t:"12m"},{p:"GitHub",h:"LeakAlert",c:"Credentials exposés: API key mali-gov.ml",t:"1h"}];
const PC:Record<string,string>={"Twitter/X":"text-sky-400","Telegram":"text-blue-400","DarkWeb":"text-red-500","GitHub":"text-gray-300"};

export function OSINTProbe(){
  return (
    <div className="space-y-2 h-full overflow-hidden">
      {OSINT_ITEMS.map((item,i)=>(
        <motion.div key={i} initial={{opacity:0,y:5}} animate={{opacity:1,y:0}} transition={{delay:i*0.1}}
          className="text-[9px] font-mono border border-cyan-900/20 rounded-sm p-1.5 hover:border-cyan-700/30 cursor-pointer">
          <div className="flex justify-between mb-0.5">
            <span className={cn("font-bold",PC[item.p]||"text-gray-400")}>{item.p}</span>
            <span className="text-gray-600">{item.t} ago</span>
          </div>
          <div className="text-cyan-600 mb-0.5">{item.h}</div>
          <div className="text-gray-300">{item.c}</div>
        </motion.div>
      ))}
    </div>
  );
}

const LOG_POOL=[{type:"BLOCKED",msg:"Intrusion attempt blocked",detail:"src:197.234.x.x → api.gov.ml",color:"text-red-400"},{type:"UPDATE",msg:"Threat feed updated",detail:"AbuseCH: +847 IOCs",color:"text-cyan-400"},{type:"ALERT",msg:"BGP anomaly detected",detail:"AS37282 route hijack attempt",color:"text-orange-400"},{type:"SCAN",msg:"Vuln scan complete",detail:"gov.sn: 3 HIGH, 7 MEDIUM",color:"text-yellow-400"},{type:"IOC",msg:"New IOC matched",detail:"SHA256: a3f9... → Emotet",color:"text-red-400"},{type:"INFO",msg:"OSINT collection running",detail:"Scanning 312 African sources",color:"text-green-400"}];

export function SystemLogs(){
  const [logs,setLogs]=useState(LOG_POOL.slice(0,3).map((l,i)=>({...l,_id:i,_time:"2024-01-01 00:00:00"})));
  useEffect(()=>{
    const iv=setInterval(()=>{
      const l=LOG_POOL[Math.floor(Math.random()*LOG_POOL.length)];
      const ts=new Date().toISOString().replace("T"," ").slice(0,19);
      setLogs(p=>[{...l,_id:Date.now(),_time:ts},...p].slice(0,5));
    },2500);
    return ()=>clearInterval(iv);
  },[]);
  return (
    <div className="h-full overflow-hidden space-y-1">
      <AnimatePresence>
        {logs.map((log:any)=>(
          <motion.div key={log._id} initial={{opacity:0,x:-10}} animate={{opacity:1,x:0}} className="flex items-start gap-2 text-[10px] font-mono">
            <span className="text-cyan-600 shrink-0 tabular-nums">{log._time}</span>
            <span className={cn("font-bold shrink-0 w-16",log.color)}>[{log.type}]</span>
            <span className="text-gray-300">{log.msg}</span>
            <span className="text-gray-500 truncate">{log.detail}</span>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
}
