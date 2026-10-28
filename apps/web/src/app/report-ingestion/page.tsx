"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { AlertCircle, CheckCircle2, Clock3, FileSearch, FileUp, RefreshCw, ShieldCheck, UploadCloud } from "lucide-react";
import AppLayout from "@/components/layout/Sidebar";
import { api } from "@/lib/api";
import { cn, SEV } from "@/lib/utils";

type ReportStatus = "pending" | "processing" | "completed" | "failed";
type Report = {
  id: string;
  organization: string;
  source_type: string;
  original_filename: string;
  sha256: string;
  size_bytes: number;
  status: ReportStatus;
  total_findings: number;
  linked_findings: number;
  unmatched_findings: number;
  summary?: { by_severity?: Record<string, number> };
  error_message?: string;
  created_at: string;
};
type Finding = {
  id: string;
  asset: string | null;
  external_asset: string;
  scanner: string;
  cve_id: string;
  cvss_score: number | null;
  severity: string;
  title: string;
  description: string;
  remediation: string;
};

const SOURCES = [
  { value: "nmap_xml", label: "Nmap XML", accept: ".xml" },
  { value: "nuclei_json", label: "Nuclei JSON", accept: ".json" },
  { value: "nuclei_jsonl", label: "Nuclei JSONL", accept: ".jsonl,.ndjson" },
  { value: "nessus_xml", label: "Nessus XML", accept: ".nessus,.xml" },
  { value: "shodan_json", label: "Shodan JSON", accept: ".json" },
  { value: "shodan_csv", label: "Shodan CSV", accept: ".csv" },
];

const STATUS_LABEL: Record<ReportStatus, string> = {
  pending: "En attente",
  processing: "Analyse en cours",
  completed: "Terminé",
  failed: "Échec",
};
const STATUS_CLASS: Record<ReportStatus, string> = {
  pending: "border-amber-400/30 bg-amber-400/10 text-amber-300",
  processing: "border-cyan-400/30 bg-cyan-400/10 text-cyan-300",
  completed: "border-emerald-400/30 bg-emerald-400/10 text-emerald-300",
  failed: "border-red-400/30 bg-red-400/10 text-red-300",
};

function getError(error: any): string {
  return error?.response?.data?.detail
    || error?.response?.data?.file?.[0]
    || error?.response?.data?.source_type?.[0]
    || error?.message
    || "Une erreur inattendue est survenue.";
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} o`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} Ko`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} Mio`;
}

export default function ReportIngestionPage() {
  const [reports, setReports] = useState<Report[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [sourceType, setSourceType] = useState("nmap_xml");
  const [organizationId, setOrganizationId] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const selected = useMemo(() => reports.find((r) => r.id === selectedId) || null, [reports, selectedId]);
  const selectedSource = SOURCES.find((s) => s.value === sourceType) || SOURCES[0];

  const loadReports = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const { data } = await api.reportIngestions.list({ page_size: 100 });
      const items = (data.results || data) as Report[];
      setReports(items);
      setSelectedId((current) => current && items.some((item) => item.id === current) ? current : (items[0]?.id || null));
      setError("");
    } catch (e) {
      setError(getError(e));
    } finally {
      if (!quiet) setLoading(false);
    }
  }, []);

  const loadFindings = useCallback(async (reportId: string) => {
    setFindingsLoading(true);
    try {
      const { data } = await api.reportIngestions.findings(reportId, { page_size: 200 });
      setFindings((data.results || data) as Finding[]);
    } catch (e) {
      setError(getError(e));
      setFindings([]);
    } finally {
      setFindingsLoading(false);
    }
  }, []);

  useEffect(() => { void loadReports(); }, [loadReports]);
  useEffect(() => {
    if (selectedId) void loadFindings(selectedId);
    else setFindings([]);
  }, [selectedId, selected?.status, loadFindings]);

  useEffect(() => {
    if (!reports.some((r) => r.status === "pending" || r.status === "processing")) return;
    const timer = window.setInterval(() => { void loadReports(true); }, 5000);
    return () => window.clearInterval(timer);
  }, [reports, loadReports]);

  async function submitReport(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!file) {
      setError("Sélectionnez un rapport avant de lancer l’import.");
      return;
    }
    if (file.size > 10 * 1024 * 1024) {
      setError("Le fichier dépasse la limite de 10 Mio.");
      return;
    }
    setUploading(true);
    setError("");
    setNotice("");
    try {
      const { data } = await api.reportIngestions.upload(file, sourceType, organizationId.trim() || undefined);
      setNotice(`Rapport reçu. Référence : ${data.id}`);
      setFile(null);
      const input = document.getElementById("report-file") as HTMLInputElement | null;
      if (input) input.value = "";
      await loadReports();
      if (data.id) setSelectedId(data.id);
    } catch (e) {
      setError(getError(e));
    } finally {
      setUploading(false);
    }
  }

  return (
    <AppLayout>
      <div className="mx-auto max-w-[1600px] space-y-5 p-5 lg:p-7">
        <header className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="mb-2 flex items-center gap-2 text-xs font-semibold tracking-[0.22em] text-cyan-400">
              <ShieldCheck className="h-4 w-4" /> BLUE TEAM / INGESTION HUB
            </div>
            <h1 className="text-2xl font-bold text-slate-100 md:text-3xl">Rapports de sécurité</h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
              Importez des rapports issus d’outils autorisés, normalisez les constats et reliez-les aux actifs inventoriés.
              Aucun scan réseau n’est lancé par cette interface.
            </p>
          </div>
          <button onClick={() => void loadReports()} disabled={loading}
            className="inline-flex items-center gap-2 rounded-lg border border-cyan-800/60 bg-slate-900 px-3 py-2 text-sm text-cyan-200 transition hover:border-cyan-500 disabled:opacity-50">
            <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} /> Actualiser
          </button>
        </header>

        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {[
            { label: "Rapports reçus", value: reports.length, icon: FileSearch },
            { label: "Constats normalisés", value: reports.reduce((sum, r) => sum + (r.total_findings || 0), 0), icon: FileSearch },
            { label: "Reliés à un actif", value: reports.reduce((sum, r) => sum + (r.linked_findings || 0), 0), icon: CheckCircle2 },
            { label: "À examiner", value: reports.reduce((sum, r) => sum + (r.unmatched_findings || 0), 0), icon: AlertCircle },
          ].map((metric) => (
            <div key={metric.label} className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
              <div className="flex items-center justify-between text-sm text-slate-400">
                {metric.label}<metric.icon className="h-4 w-4 text-cyan-400" />
              </div>
              <div className="mt-3 text-2xl font-semibold tabular-nums text-slate-100">{metric.value.toLocaleString("fr-FR")}</div>
            </div>
          ))}
        </div>

        {error && <div role="alert" className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-200"><AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />{error}</div>}
        {notice && <div role="status" className="flex items-start gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm text-emerald-200"><CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />{notice}</div>}

        <section className="grid items-start gap-5 xl:grid-cols-[minmax(320px,0.8fr)_minmax(0,1.4fr)]">
          <form onSubmit={submitReport} className="space-y-4 rounded-xl border border-slate-800 bg-slate-900/70 p-5">
            <div className="flex items-center gap-2">
              <UploadCloud className="h-5 w-5 text-cyan-400" />
              <h2 className="font-semibold text-slate-100">Importer un rapport</h2>
            </div>
            <label className="block text-sm text-slate-300" htmlFor="source-type">Format du rapport</label>
            <select id="source-type" value={sourceType} onChange={(e) => setSourceType(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-slate-100 outline-none focus:border-cyan-500">
              {SOURCES.map((source) => <option key={source.value} value={source.value}>{source.label}</option>)}
            </select>
            <div>
              <label className="mb-1 block text-sm text-slate-300" htmlFor="organization-id">Organisation (admin global uniquement)</label>
              <input id="organization-id" value={organizationId} onChange={(e) => setOrganizationId(e.target.value)}
                placeholder="UUID de l’organisation, si nécessaire"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-slate-100 outline-none placeholder:text-slate-600 focus:border-cyan-500" />
              <p className="mt-1 text-xs text-slate-500">Pour les comptes rattachés à une organisation, ce champ peut rester vide.</p>
            </div>
            <label htmlFor="report-file" className="flex min-h-40 cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed border-cyan-800/70 bg-slate-950/70 px-5 py-7 text-center transition hover:border-cyan-500">
              <FileUp className="mb-3 h-8 w-8 text-cyan-400" />
              <span className="text-sm font-medium text-slate-200">{file?.name || "Choisir un fichier"}</span>
              <span className="mt-2 text-xs text-slate-500">Taille maximale : 10 Mio · {selectedSource.accept}</span>
              <input id="report-file" type="file" accept={selectedSource.accept} className="sr-only"
                onChange={(e) => setFile(e.target.files?.[0] || null)} />
            </label>
            {file && <div className="flex items-center justify-between text-xs text-slate-400"><span>{formatBytes(file.size)}</span><button type="button" onClick={() => { setFile(null); const input = document.getElementById("report-file") as HTMLInputElement | null; if (input) input.value = ""; }} className="text-slate-300 hover:text-white">Retirer</button></div>}
            <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-xs leading-5 text-amber-100/80">
              Importez uniquement des rapports que votre organisation est autorisée à traiter. Les données de cibles inconnues restent non associées pour vérification.
            </div>
            <button type="submit" disabled={!file || uploading}
              className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-cyan-500 px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50">
              {uploading ? <><RefreshCw className="h-4 w-4 animate-spin" /> Import en cours…</> : <><UploadCloud className="h-4 w-4" /> Envoyer et analyser</>}
            </button>
          </form>

          <div className="min-w-0 rounded-xl border border-slate-800 bg-slate-900/70">
            <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
              <div>
                <h2 className="font-semibold text-slate-100">Historique des imports</h2>
                <p className="mt-1 text-xs text-slate-500">Le statut se rafraîchit automatiquement pendant le traitement.</p>
              </div>
              <span className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-400">{reports.length} rapport(s)</span>
            </div>
            {loading ? <div className="p-8 text-center text-sm text-slate-500">Chargement des rapports…</div>
              : reports.length === 0 ? <div className="p-8 text-center text-sm text-slate-500">Aucun rapport importé pour cette organisation.</div>
              : <div className="max-h-[520px] overflow-auto">
                <table className="w-full min-w-[620px] text-left text-sm">
                  <thead className="sticky top-0 bg-slate-950/95 text-xs uppercase tracking-wider text-slate-500">
                    <tr><th className="px-4 py-3 font-medium">Rapport</th><th className="px-4 py-3 font-medium">Format</th><th className="px-4 py-3 font-medium">Statut</th><th className="px-4 py-3 font-medium">Constats</th></tr>
                  </thead>
                  <tbody>
                    {reports.map((report) => (
                      <tr key={report.id} onClick={() => setSelectedId(report.id)} tabIndex={0}
                        onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") setSelectedId(report.id); }}
                        className={cn("cursor-pointer border-t border-slate-800/80 transition hover:bg-cyan-950/30", selectedId === report.id && "bg-cyan-950/30")}>
                        <td className="max-w-[240px] px-4 py-3">
                          <div className="truncate font-medium text-slate-200">{report.original_filename}</div>
                          <div className="mt-1 text-xs text-slate-500">{new Date(report.created_at).toLocaleString("fr-FR")}</div>
                        </td>
                        <td className="px-4 py-3 text-xs text-slate-400">{SOURCES.find((s) => s.value === report.source_type)?.label || report.source_type}</td>
                        <td className="px-4 py-3"><span className={cn("inline-flex rounded-full border px-2 py-1 text-xs", STATUS_CLASS[report.status] || STATUS_CLASS.pending)}>{STATUS_LABEL[report.status] || report.status}</span></td>
                        <td className="px-4 py-3 tabular-nums text-slate-300">{report.total_findings}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>}
          </div>
        </section>

        <section className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/70">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 px-5 py-4">
            <div>
              <h2 className="font-semibold text-slate-100">Constats normalisés</h2>
              <p className="mt-1 text-xs text-slate-500">{selected ? selected.original_filename : "Sélectionnez un rapport dans l’historique."}</p>
            </div>
            {selected && <div className="flex flex-wrap gap-3 text-xs text-slate-400"><span>Reliés : <b className="text-emerald-300">{selected.linked_findings}</b></span><span>Non associés : <b className="text-amber-300">{selected.unmatched_findings}</b></span></div>}
          </div>
          {!selected ? <div className="p-8 text-center text-sm text-slate-500">Aucun rapport sélectionné.</div>
            : selected.status === "failed" ? <div className="p-5 text-sm text-red-200">{selected.error_message || "Le traitement a échoué."}</div>
            : findingsLoading ? <div className="p-8 text-center text-sm text-slate-500">Chargement des constats…</div>
            : findings.length === 0 ? <div className="p-8 text-center text-sm text-slate-500">{selected.status === "completed" ? "Aucun constat dans ce rapport." : "Les constats apparaîtront lorsque le traitement sera terminé."}</div>
            : <div className="overflow-x-auto">
              <table className="w-full min-w-[780px] text-left text-sm">
                <thead className="bg-slate-950/70 text-xs uppercase tracking-wider text-slate-500">
                  <tr><th className="px-4 py-3 font-medium">Sévérité</th><th className="px-4 py-3 font-medium">Constat</th><th className="px-4 py-3 font-medium">CVE / CVSS</th><th className="px-4 py-3 font-medium">Cible du rapport</th><th className="px-4 py-3 font-medium">Association</th></tr>
                </thead>
                <tbody>
                  {findings.map((finding) => (
                    <tr key={finding.id} className="border-t border-slate-800/80 align-top">
                      <td className="px-4 py-3"><span className={cn("inline-flex rounded-full border px-2 py-1 text-xs", SEV[finding.severity]?.text, SEV[finding.severity]?.bg, SEV[finding.severity]?.border)}>{finding.severity?.toUpperCase()}</span></td>
                      <td className="max-w-md px-4 py-3"><div className="font-medium text-slate-200">{finding.title}</div><p className="mt-1 line-clamp-2 text-xs leading-5 text-slate-500">{finding.description}</p></td>
                      <td className="whitespace-nowrap px-4 py-3 text-xs text-slate-400">{finding.cve_id || "—"}<div className="mt-1">CVSS {finding.cvss_score ?? "—"}</div></td>
                      <td className="max-w-[220px] break-words px-4 py-3 text-xs text-slate-400">{finding.external_asset || "Cible non précisée"}</td>
                      <td className="px-4 py-3 text-xs">{finding.asset ? <span className="text-emerald-300">Actif inventorié</span> : <span className="text-amber-300">À vérifier</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>}
          {selected && <div className="flex flex-wrap items-center gap-2 border-t border-slate-800 px-5 py-3 text-xs text-slate-500"><Clock3 className="h-3.5 w-3.5" /> SHA-256 : <code className="break-all text-slate-400">{selected.sha256}</code></div>}
        </section>
      </div>
    </AppLayout>
  );
}
