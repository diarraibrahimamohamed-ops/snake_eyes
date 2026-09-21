"use client";
import { useEffect, useMemo, useState } from "react";
import { Crosshair, RefreshCw, ShieldCheck, Clock, Play, LockKeyhole, Zap, Ban } from "lucide-react";
import AppLayout from "@/components/layout/Sidebar";
import { api } from "@/lib/api";

const PROFILES = [
  ["dns_recon", "DNS"], ["dns_posture", "DNS POSTURE"], ["web_recon", "WEB"], ["web_posture", "WEB POSTURE"], ["tls_audit", "TLS"],
  ["port_recon", "PORTS"], ["exposure_audit", "EXPOSURE"], ["adversary_recon", "ADVERSARY RECON"],
  ["exposure_chain", "ATTACK CHAIN"], ["nuclei_safe", "NUCLEI SAFE"], ["combined_recon", "COMBINED"],
] as const;

export default function OffensiveLabPage() {
  const [engagements, setEngagements] = useState<any[]>([]);
  const [jobs, setJobs] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [assets, setAssets] = useState<any[]>([]);
  const [me, setMe] = useState<any>(null);
  const [name, setName] = useState("");
  const [authRef, setAuthRef] = useState("");
  const [assetId, setAssetId] = useState("");
  const [startsAt, setStartsAt] = useState("");
  const [endsAt, setEndsAt] = useState("");
  const [creating, setCreating] = useState(false);
  const [profile, setProfile] = useState("exposure_audit");
  const [intel, setIntel] = useState<any>(null);
  const [selectedReport, setSelectedReport] = useState<any>(null);

  const load = async () => {
    setLoading(true);
    try {
      const [e, j, m, a, f] = await Promise.all([
        api.offensive.engagements(), api.offensive.jobs(), api.users.me(), api.assets.list({page_size:100}), api.offensive.findings(),
      ]);
      setEngagements(e.data.results || e.data); setJobs(j.data.results || j.data);
      setMe(m.data); setAssets(a.data.results || a.data); setFindings(f.data || []);
    } finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const createEngagement = async () => {
    if (!name || !authRef || !assetId || !startsAt || !endsAt || !me?.organization) return;
    setCreating(true);
    try {
      const { data } = await api.offensive.createEngagement({
        organization: me.organization, name, authorization_reference: authRef,
        starts_at: new Date(startsAt).toISOString(), ends_at: new Date(endsAt).toISOString(),
        status: "draft", lab_mode: false,
        max_targets: 25, max_jobs_per_hour: 20, max_concurrent_jobs: 2,
      });
      await api.offensive.createTarget({ engagement: data.id, asset: assetId, enabled: true });
      setName(""); setAuthRef(""); setAssetId(""); await load();
    } finally { setCreating(false); }
  };
  const launch = async (engagement: any, p: string) => {
    if (!engagement.approved) return;
    const preflight = await api.offensive.preflight(engagement.id);
    setIntel({ type: "preflight", engagement: engagement.name, data: preflight.data });
    if (!preflight.data.ready) return;
    await api.offensive.launch(engagement.id, p); await load();
  };
  const inspectPlan = async (engagement: any) => {
    const [preflight, plan] = await Promise.all([
      api.offensive.preflight(engagement.id),
      api.offensive.adversaryPlan(engagement.id),
    ]);
    setIntel({ type: "adversary_plan", engagement: engagement.name, preflight: preflight.data, plan: plan.data });
  };
  const launchBatch = async (engagement: any) => {
    if (!engagement.approved) return;
    const preflight = await api.offensive.preflight(engagement.id);
    setIntel({ type: "preflight", engagement: engagement.name, data: preflight.data });
    if (!preflight.data.ready) return;
    const plan = await api.offensive.adversaryPlan(engagement.id);
    setIntel({ type: "plan", engagement: engagement.name, data: plan.data });
    await api.offensive.launchBatch(engagement.id, profile); await load();
  };
  const cancel = async (job: any) => { await api.offensive.cancel(job.id); await load(); };
  const inspectJob = async (job: any) => { const { data } = await api.offensive.report(job.id); setSelectedReport(data); };
  const highFindings = useMemo(() => findings.filter(f => ["high", "critical"].includes(f.severity)).length, [findings]);

  return <AppLayout><div className="p-4 space-y-5">
    <header className="flex items-center justify-between"><div>
      <div className="flex items-center gap-2 text-cyan-300"><Crosshair className="w-5 h-5"/><h1 className="text-base font-bold tracking-widest">OFFENSIVE LAB // CONTROLLED</h1></div>
      <p className="text-xs text-gray-500 mt-1">Threat-informed red team • scope verrouillé • attack-path • drift • télémétrie • aucune exploitation autonome</p>
    </div><button onClick={load} className="p-2 border border-cyan-900/40 text-cyan-500 rounded-sm"><RefreshCw className="w-4 h-4"/></button></header>
    <div className="grid grid-cols-4 gap-3">
      <div className="bg-[#0a1628] border border-cyan-900/30 p-3 rounded-sm"><ShieldCheck className="w-4 h-4 text-green-400 mb-2"/><div className="text-[10px] text-gray-500 tracking-widest">ENGAGEMENTS AUTORISÉS</div><div className="text-2xl text-cyan-300 font-bold">{engagements.filter(e=>e.approved).length}</div></div>
      <div className="bg-[#0a1628] border border-cyan-900/30 p-3 rounded-sm"><Clock className="w-4 h-4 text-orange-400 mb-2"/><div className="text-[10px] text-gray-500 tracking-widest">JOBS</div><div className="text-2xl text-cyan-300 font-bold">{jobs.length}</div></div>
      <div className="bg-[#0a1628] border border-cyan-900/30 p-3 rounded-sm"><Zap className="w-4 h-4 text-yellow-400 mb-2"/><div className="text-[10px] text-gray-500 tracking-widest">HIGH/CRITICAL</div><div className="text-2xl text-yellow-300 font-bold">{highFindings}</div></div>
      <div className="bg-[#0a1628] border border-cyan-900/30 p-3 rounded-sm"><LockKeyhole className="w-4 h-4 text-red-400 mb-2"/><div className="text-[10px] text-gray-500 tracking-widest">POLICY</div><div className="text-sm text-gray-300 mt-1">Actifs enregistrés uniquement</div></div>
    </div>
    <section className="bg-[#0a1628] border border-cyan-900/30 p-3 rounded-sm space-y-3">
      <div className="text-[10px] tracking-widest text-gray-500">NOUVEL ENGAGEMENT</div>
      <div className="grid grid-cols-5 gap-2">
        <input value={name} onChange={e=>setName(e.target.value)} placeholder="Nom de mission" className="bg-[#060d1a] border border-cyan-900/30 px-2 py-2 text-xs text-gray-300 rounded-sm"/>
        <input value={authRef} onChange={e=>setAuthRef(e.target.value)} placeholder="Référence autorisation" className="bg-[#060d1a] border border-cyan-900/30 px-2 py-2 text-xs text-gray-300 rounded-sm"/>
        <select value={assetId} onChange={e=>setAssetId(e.target.value)} className="bg-[#060d1a] border border-cyan-900/30 px-2 py-2 text-xs text-gray-300 rounded-sm"><option value="">Actif à intégrer</option>{assets.map(a=><option key={a.id} value={a.id}>{a.name} — {a.value}</option>)}</select>
        <input type="datetime-local" value={startsAt} onChange={e=>setStartsAt(e.target.value)} className="bg-[#060d1a] border border-cyan-900/30 px-2 py-2 text-xs text-gray-300 rounded-sm"/>
        <div className="flex gap-2"><input type="datetime-local" value={endsAt} onChange={e=>setEndsAt(e.target.value)} className="min-w-0 flex-1 bg-[#060d1a] border border-cyan-900/30 px-2 py-2 text-xs text-gray-300 rounded-sm"/><button disabled={creating} onClick={createEngagement} className="px-3 border border-cyan-500/30 text-cyan-300 text-[9px] rounded-sm disabled:opacity-30">CRÉER</button></div>
      </div>
    </section>
    <section><div className="text-[10px] tracking-widest text-gray-500 mb-2">ENGAGEMENTS & PROFILS</div><div className="space-y-2">
      {loading ? <div className="text-gray-500 text-sm">Chargement...</div> : engagements.length === 0 ? <div className="text-gray-500 text-sm border border-cyan-900/20 p-4">Aucun engagement.</div> : engagements.map(e => <div key={e.id} className="bg-[#0a1628] border border-cyan-900/30 p-3 rounded-sm">
        <div className="flex justify-between gap-3"><div><div className="text-sm text-gray-200">{e.name}</div><div className="text-[10px] text-gray-500 mt-1">AUTH: {e.authorization_reference} • CIBLES: {e.target_count ?? 0} • MAX JOB/H: {e.max_jobs_per_hour}</div></div><div className="text-[10px] font-bold uppercase text-cyan-400">{e.status} {e.approved ? "• APPROUVÉ" : ""}</div></div>
        <div className="flex flex-wrap gap-2 mt-3">{PROFILES.map(([p,label]) => <button key={p} onClick={()=>launch(e,p)} disabled={!e.approved || (e.allowed_profiles?.length && !e.allowed_profiles.includes(p))} className="text-[9px] border border-cyan-900/40 px-2 py-1.5 text-gray-400 hover:text-cyan-300 disabled:opacity-30 flex items-center gap-1"><Play className="w-3 h-3"/>{label}</button>)}
          <select value={profile} onChange={x=>setProfile(x.target.value)} className="text-[9px] bg-[#060d1a] border border-cyan-900/30 px-2 py-1.5 text-gray-300"><option value="exposure_audit">BATCH: EXPOSURE</option><option value="adversary_recon">BATCH: ADVERSARY RECON</option><option value="combined_recon">BATCH: COMBINED</option><option value="nuclei_safe">BATCH: NUCLEI SAFE</option></select>
          <button onClick={()=>inspectPlan(e)} className="text-[9px] border border-purple-900/40 px-2 py-1.5 text-purple-300 flex items-center gap-1">RED-TEAM PLAN</button>
          <button onClick={()=>launchBatch(e)} disabled={!e.approved} className="text-[9px] border border-yellow-900/40 px-2 py-1.5 text-yellow-300 disabled:opacity-30 flex items-center gap-1"><Zap className="w-3 h-3"/>BATCH</button>
        </div>
      </div>)}
    </div></section>
    <section><div className="text-[10px] tracking-widest text-gray-500 mb-2">DERNIERS JOBS</div><div className="bg-[#0a1628] border border-cyan-900/30 divide-y divide-cyan-900/20">{jobs.slice(0,15).map(j=><div key={j.id} className="p-3 flex items-center justify-between gap-3 text-xs"><span className="text-gray-300">{j.profile} • {j.status} • findings:{j.finding_count ?? 0}</span><div className="flex gap-2"><button onClick={()=>inspectJob(j)} className="text-cyan-500 hover:text-cyan-300">REPORT</button><button onClick={()=>cancel(j)} disabled={!['queued','running'].includes(j.status)} className="text-gray-500 hover:text-red-300 disabled:opacity-20"><Ban className="w-3 h-3"/></button></div></div>)}{!jobs.length&&<div className="p-4 text-gray-500">Aucun job.</div>}</div></section>
    {intel && <section><div className="text-[10px] tracking-widest text-gray-500 mb-2">RED-TEAM INTELLIGENCE</div><pre className="bg-[#0a1628] border border-cyan-900/30 p-3 overflow-auto text-[10px] text-gray-400 max-h-72">{JSON.stringify(intel, null, 2)}</pre></section>}
    {selectedReport && <section><div className="text-[10px] tracking-widest text-gray-500 mb-2">ATTACK SURFACE / DRIFT / INTEGRITY</div><pre className="bg-[#0a1628] border border-cyan-900/30 p-3 overflow-auto text-[10px] text-gray-400 max-h-96">{JSON.stringify(selectedReport, null, 2)}</pre></section>}
    <section><div className="text-[10px] tracking-widest text-gray-500 mb-2">FINDINGS LATEST</div><div className="bg-[#0a1628] border border-cyan-900/30 divide-y divide-cyan-900/20">{findings.slice(0,12).map(f=><div key={f.id} className="p-3 text-xs"><div className="flex justify-between gap-2"><span className="text-gray-200">{f.title}</span><span className="uppercase text-cyan-300">{f.severity}</span></div><div className="text-gray-500 mt-1">{f.category} • confiance {Math.round((f.confidence||0)*100)}%</div></div>)}{!findings.length&&<div className="p-4 text-gray-500">Aucun finding.</div>}</div></section>
  </div></AppLayout>;
}
