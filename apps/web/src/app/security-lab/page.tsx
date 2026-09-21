"use client";
import { useEffect, useState } from "react";
import { ShieldCheck, Play, RefreshCw, Lock, Database, KeyRound, Bug, ScanSearch } from "lucide-react";
import AppLayout from "@/components/layout/Sidebar";
import api from "@/lib/api";

type Tool = { slug:string; name:string; category:string; mode:string; description:string; executable:string; safety_boundary:string; default_enabled:boolean };
type Review = { id:string; profile:string; status:string; input_ref:string; asset?:string; findings_count:number; created_at:string; result:any; error_message?:string };

const PROFILES = [
  ["owasp_web","OWASP Web 2025"],["owasp_api","OWASP API 2023"],["db_posture","Database Posture"],
  ["db_code_surface","SQL/DB Code Surface"],["local_code","SAST / SCA"],["local_container","Trivy filesystem"],
  ["local_secrets","Gitleaks"],["local_credential","John — offline"],["zap_baseline_plan","ZAP Baseline — plan"],
  ["hydra_readiness","Hydra — readiness"],["sqlmap_readiness","sqlmap — readiness"],["toolchain","Toolchain Health"],
] as const;

export default function SecurityLabPage(){
  const [tools,setTools]=useState<Tool[]>([]); const [reviews,setReviews]=useState<Review[]>([]); const [assets,setAssets]=useState<any[]>([]); const [profile,setProfile]=useState("owasp_web");
  const [asset,setAsset]=useState(""); const [inputRef,setInputRef]=useState(""); const [selected,setSelected]=useState<any>(null); const [loading,setLoading]=useState(false);
  const load=async()=>{ const [t,r,a]=await Promise.all([api.security.tools(),api.security.reviews(),api.assets.list({page_size:100})]); setTools(t.data.results||t.data); setReviews(r.data.results||r.data); setAssets(a.data.results||a.data); };
  useEffect(()=>{ load(); },[]);
  const create=async()=>{setLoading(true); try{ const r=await api.security.createReview({profile,asset:asset||null,input_ref:inputRef,tool:profile.split("_")[0]}); await api.security.run(r.data.id); await load(); } finally {setLoading(false);} };
  const inspect=async(id:string)=>{ const [r,f]=await Promise.all([api.security.reviews(),api.security.findings(id)]); const one=(r.data.results||r.data).find((x:Review)=>x.id===id); setSelected({review:one,findings:f.data.results||f.data}); };
  return <AppLayout><div className="p-6 max-w-7xl mx-auto text-gray-300 space-y-6">
    <header className="flex justify-between items-start"><div><div className="text-[10px] tracking-[.3em] text-cyan-500">AFRICAWATCH / SECURITY LAB</div><h1 className="text-2xl font-semibold text-white mt-1">Application • Database • Credential • Supply Chain</h1><p className="text-xs text-gray-500 mt-2 max-w-3xl">OWASP 2025 / API 2023, lecture seule côté base de données, audits locaux, DAST baseline et préparation encadrée des outils offensifs.</p></div><button onClick={load} className="border border-cyan-900/40 p-2"><RefreshCw className="w-4 h-4"/></button></header>
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
      <section className="lg:col-span-2 bg-[#0a1628] border border-cyan-900/30 p-4"><div className="text-[10px] tracking-widest text-gray-500 mb-3">LANCER UNE REVUE</div><div className="grid md:grid-cols-2 gap-3">
        <select value={profile} onChange={e=>setProfile(e.target.value)} className="bg-[#060d1a] border border-cyan-900/30 p-2 text-xs">{PROFILES.map(([v,l])=><option key={v} value={v}>{l}</option>)}</select>
        <select value={asset} onChange={e=>setAsset(e.target.value)} className="bg-[#060d1a] border border-cyan-900/30 p-2 text-xs"><option value="">{profile==="owasp_web"?"Sélectionner un actif":"Actif optionnel"}</option>{assets.map(a=><option key={a.id} value={a.id}>{a.name} — {a.value}</option>)}</select>
        <textarea value={inputRef} onChange={e=>setInputRef(e.target.value)} placeholder="Entrée : OpenAPI JSON, profil DB serveur, chemin de labo, ou target::service pour plan Hydra" className="md:col-span-2 bg-[#060d1a] border border-cyan-900/30 p-2 text-xs min-h-28"/>
        <button disabled={loading} onClick={create} className="md:col-span-2 bg-cyan-600/10 border border-cyan-500/30 py-2 text-xs text-cyan-300 disabled:opacity-40 flex items-center justify-center gap-2"><Play className="w-3 h-3"/>{loading?"ENFILEMENT…":"LANCER LA REVUE"}</button>
      </div></section>
      <section className="bg-[#0a1628] border border-cyan-900/30 p-4"><div className="text-[10px] tracking-widest text-gray-500 mb-3">OUTILS DISPONIBLES</div>{tools.map(t=><div key={t.slug} className="border-b border-cyan-900/20 py-2"><div className="flex justify-between text-xs"><span>{t.name}</span><span className="text-[9px] text-cyan-500">{t.mode}</span></div><div className="text-[9px] text-gray-600 mt-1">{t.safety_boundary}</div></div>)}</section>
    </div>
    <section className="bg-[#0a1628] border border-cyan-900/30"><div className="p-4 border-b border-cyan-900/20 text-[10px] tracking-widest text-gray-500">REVUES RÉCENTES</div>{reviews.slice(0,25).map(r=><div key={r.id} className="p-3 border-b border-cyan-900/20 flex items-center justify-between"><div className="flex gap-3 items-center"><ScanSearch className="w-4 h-4 text-cyan-500"/><div><div className="text-xs text-white">{r.profile}</div><div className="text-[9px] text-gray-600">{r.status} • findings {r.findings_count || 0} • {r.input_ref || "asset-scoped"}</div></div></div><button onClick={()=>inspect(r.id)} className="text-[9px] text-cyan-500">INSPECTER</button></div>)}{!reviews.length&&<div className="p-5 text-xs text-gray-600">Aucune revue.</div>}</section>
    {selected&&<section className="bg-[#0a1628] border border-cyan-900/30 p-4"><div className="grid md:grid-cols-4 gap-3 mb-4"><div className="p-3 border border-cyan-900/20"><Lock className="w-4 h-4 text-cyan-500"/><div className="text-xs mt-2">{selected.review.profile}</div></div><div className="p-3 border border-cyan-900/20"><Database className="w-4 h-4 text-cyan-500"/><div className="text-xs mt-2">{selected.findings.length} findings</div></div><div className="p-3 border border-cyan-900/20"><KeyRound className="w-4 h-4 text-cyan-500"/><div className="text-xs mt-2">No secrets persisted by scanner</div></div><div className="p-3 border border-cyan-900/20"><Bug className="w-4 h-4 text-cyan-500"/><div className="text-xs mt-2">{selected.review.status}</div></div></div><pre className="text-[10px] text-gray-500 overflow-auto max-h-96">{JSON.stringify(selected,null,2)}</pre></section>}
  </div></AppLayout>
}
