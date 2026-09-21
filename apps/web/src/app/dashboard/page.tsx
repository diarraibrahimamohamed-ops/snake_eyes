"use client";
import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Shield, Wifi, WifiOff } from "lucide-react";
import { ThreatMap } from "@/components/dashboard/ThreatMap";
import { ThreatTicker, StatsGrid, ThreatScoreGauge, LiveAlertFeed, IOCStream, OSINTProbe, SystemLogs } from "@/components/dashboard/index";
import { useDashboardStore } from "@/lib/stores/dashboard";
import { useWebSocket } from "@/hooks/useWebSocket";
import { cn } from "@/lib/utils";

function Card({title,badge,badgeColor="cyan",children,className}:{title:string;badge?:string;badgeColor?:string;children:React.ReactNode;className?:string}){
  const BC:Record<string,string>={red:"text-red-400 border-red-400/30 bg-red-400/10",cyan:"text-cyan-400 border-cyan-400/30 bg-cyan-400/10",orange:"text-orange-400 border-orange-400/30 bg-orange-400/10",purple:"text-purple-400 border-purple-400/30 bg-purple-400/10",green:"text-green-400 border-green-400/30 bg-green-400/10"};
  return (
    <motion.div initial={{opacity:0,y:8}} animate={{opacity:1,y:0}} className={cn("relative bg-[#0a1628]/80 border border-cyan-900/40 rounded-sm flex flex-col hover:border-cyan-700/50 transition-colors",className)}>
      {["top-0 left-0 border-t border-l","top-0 right-0 border-t border-r","bottom-0 left-0 border-b border-l","bottom-0 right-0 border-b border-r"].map((c,i)=>(
        <div key={i} className={`absolute w-3 h-3 ${c} border-cyan-500/50`}/>
      ))}
      <div className="flex items-center justify-between px-3 py-2 border-b border-cyan-900/30">
        <span className="text-[11px] font-bold tracking-[0.15em] text-cyan-300">{title}</span>
        {badge&&<span className={cn("text-[9px] tracking-widest border px-2 py-0.5 rounded-sm font-bold",BC[badgeColor]||BC.cyan)}>{badge}</span>}
      </div>
      <div className="flex-1 overflow-hidden p-2">{children}</div>
    </motion.div>
  );
}

export default function DashboardPage() {
  const {threatScore,alerts,iocs,isConnected}=useDashboardStore();
  const [time,setTime]=useState(null);
  const [mounted,setMounted]=useState(false);
  useWebSocket();
  useEffect(()=>{
    setMounted(true);
    setTime(new Date());
    const t=setInterval(()=>setTime(new Date()),1000);
    return ()=>clearInterval(t);
  },[]);

  return (
    <div className="min-h-screen bg-[#060d1a] text-white font-mono overflow-hidden">
      <header className="border-b border-cyan-900/40 bg-[#07101f]/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="flex items-center justify-between px-5 py-3">
          <div className="flex items-center gap-3">
            <div className="relative">
              <Shield className="w-7 h-7 text-cyan-400"/>
              <motion.div className="absolute inset-0 border border-cyan-400/30 rounded-full" animate={{scale:[1,1.5],opacity:[0.5,0]}} transition={{duration:2,repeat:Infinity}}/>
            </div>
            <div>
              <h1 className="text-base font-bold tracking-[0.25em] text-cyan-400">AFRICANWATCH</h1>
              <p className="text-[9px] text-cyan-600 tracking-widest">CYBER INTELLIGENCE PLATFORM</p>
            </div>
          </div>
          <ThreatTicker/>
          <div className="flex items-center gap-3 text-[10px]">
            <div className="flex items-center gap-1.5">
              {isConnected?<><motion.div className="w-2 h-2 rounded-full bg-green-400" animate={{opacity:[1,0.3,1]}} transition={{duration:1.5,repeat:Infinity}}/><Wifi className="w-3.5 h-3.5 text-green-400"/><span className="text-green-400 tracking-wider">LIVE</span></>:<><div className="w-2 h-2 rounded-full bg-red-500"/><WifiOff className="w-3.5 h-3.5 text-red-500"/><span className="text-red-500">OFFLINE</span></>}
            </div>
            <span className="text-cyan-600 tabular-nums text-[9px]">{mounted && time ? time.toUTCString().replace("GMT","UTC") : ""}</span>
          </div>
        </div>
      </header>
      <StatsGrid/>
      <main className="p-3 grid grid-cols-12 gap-3">
        <div className="col-span-7 row-span-2">
          <Card title="GLOBAL THREAT LANDSCAPE" badge={`${NODES_CRITICAL} CRITICAL`} badgeColor="red" className="h-[480px]">
            <ThreatMap/>
          </Card>
        </div>
        <div className="col-span-2">
          <Card title="THREAT SCORE" className="h-[232px]">
            <ThreatScoreGauge score={threatScore.score} level={threatScore.level}/>
          </Card>
        </div>
        <div className="col-span-3">
          <Card title="IOC STREAM" badge="LIVE" badgeColor="cyan" className="h-[232px]">
            <IOCStream iocs={iocs.slice(0,8) as any}/>
          </Card>
        </div>
        <div className="col-span-2">
          <Card title="LIVE ALERTS" badge={`${alerts.filter((a:any)=>a.status==="new").length||5} NEW`} badgeColor="orange" className="h-[234px]">
            <LiveAlertFeed alerts={alerts.slice(0,5) as any}/>
          </Card>
        </div>
        <div className="col-span-3">
          <Card title="OSINT PROBE" badge="SCANNING" badgeColor="purple" className="h-[234px]">
            <OSINTProbe/>
          </Card>
        </div>
        <div className="col-span-12">
          <Card title="SYSTEM LOGS" badge="TERMINAL" badgeColor="green" className="h-[130px]">
            <SystemLogs/>
          </Card>
        </div>
      </main>
    </div>
  );
}
const NODES_CRITICAL = 4;
