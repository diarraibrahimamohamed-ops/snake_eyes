"use client";
import { useEffect, useRef } from "react";
import { useDashboardStore } from "@/lib/stores/dashboard";
export function useWebSocket() {
  const {setConnected,addAlert,addIOC,setThreatScore,setStats}=useDashboardStore();
  const wsRef=useRef<WebSocket|null>(null);
  const retryRef=useRef<ReturnType<typeof setTimeout>>();
  useEffect(()=>{
    const wsUrl=process.env.NEXT_PUBLIC_WS_URL||"ws://localhost:8000";
    function connect(){
      try {
        const ws=new WebSocket(`${wsUrl}/ws/dashboard/`);
        wsRef.current=ws;
        ws.onopen=()=>setConnected(true);
        ws.onclose=()=>{ setConnected(false); retryRef.current=setTimeout(connect,5000); };
        ws.onerror=()=>setConnected(false);
        ws.onmessage=(e)=>{
          try {
            const {type,payload}=JSON.parse(e.data);
            if(type==="alert.new") addAlert(payload);
            else if(type==="ioc.new") addIOC(payload);
            else if(type==="threat_score.update") setThreatScore(payload);
            else if(type==="stats.update") setStats(payload);
          } catch {}
        };
      } catch { setConnected(false); retryRef.current=setTimeout(connect,5000); }
    }
    connect();
    return ()=>{ clearTimeout(retryRef.current); wsRef.current?.close(); };
  },[]);
}
