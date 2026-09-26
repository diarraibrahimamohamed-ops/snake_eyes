import axios, { AxiosInstance } from "axios";
const BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

class APIClient {
  private http: AxiosInstance;
  constructor() {
    this.http = axios.create({ baseURL: `${BASE}/api/v1`, timeout: 30000 });
    this.http.interceptors.request.use(cfg => {
      if (typeof window !== "undefined") {
        const t = sessionStorage.getItem("aw_access");
        if (t) cfg.headers.Authorization = `Bearer ${t}`;
      }
      return cfg;
    });
    this.http.interceptors.response.use(r => r, async err => {
      const orig = err.config;
      if (err.response?.status === 401 && !orig._retry) {
        orig._retry = true;
        try {
          const ref = typeof window !== "undefined" ? sessionStorage.getItem("aw_refresh") : null;
          if (!ref) { this.logout(); return Promise.reject(err); }
          const { data } = await axios.post(`${BASE}/api/v1/auth/token/refresh/`, { refresh: ref });
          sessionStorage.setItem("aw_access", data.access);
          orig.headers.Authorization = `Bearer ${data.access}`;
          return this.http(orig);
        } catch { this.logout(); }
      }
      return Promise.reject(err);
    });
  }
  async login(email: string, password: string) {
    const { data } = await this.http.post("/auth/token/", { email, password });
    sessionStorage.setItem("aw_access", data.access);
    sessionStorage.setItem("aw_refresh", data.refresh);
    return data;
  }
  logout() {
    if (typeof window !== "undefined") {
      sessionStorage.removeItem("aw_access");
      sessionStorage.removeItem("aw_refresh");
      window.location.href = "/login";
    }
  }
  iocs = {
    list: (p?: any) => this.http.get("/iocs/", { params: p }),
    stats: () => this.http.get("/iocs/stats/"),
    lookup: (value: string) => this.http.get("/iocs/lookup/", { params: { value } }),
    create: (d: any) => this.http.post("/iocs/", d),
    bulkImport: (iocs: any[]) => this.http.post("/iocs/bulk-import/", { iocs }),
    markFP: (id: string) => this.http.post(`/iocs/${id}/false-positive/`),
    enrich: (id: string) => this.http.post(`/iocs/${id}/enrich/`),
  };
  feeds = {
    list: (p?: any) => this.http.get("/feeds/", { params: p }),
    fetch: (id: string) => this.http.post(`/feeds/${id}/fetch/`),
  };
  alerts = {
    list: (p?: any) => this.http.get("/alerts/", { params: p }),
    stats: () => this.http.get("/alerts/stats/"),
    acknowledge: (id: string) => this.http.post(`/alerts/${id}/acknowledge/`),
    escalate: (id: string, d?: any) => this.http.post(`/alerts/${id}/escalate/`, d),
    markFP: (id: string, d?: any) => this.http.post(`/alerts/${id}/false-positive/`, d),
  };
  incidents = {
    list: (p?: any) => this.http.get("/incidents/", { params: p }),
    get: (id: string) => this.http.get(`/incidents/${id}/`),
    create: (d: any) => this.http.post("/incidents/", d),
    addTimeline: (id: string, d: any) => this.http.post(`/incidents/${id}/add-timeline/`, d),
    changeStatus: (id: string, status: string) => this.http.post(`/incidents/${id}/change-status/`, { status }),
    stats: () => this.http.get("/incidents/stats/"),
  };
  osint = {
    events: (p?: any) => this.http.get("/osint/events/", { params: p }),
    sources: (p?: any) => this.http.get("/osint/sources/", { params: p }),
    stats: () => this.http.get("/osint/events/stats/"),
    collect: (id: string) => this.http.post(`/osint/sources/${id}/collect/`),
  };
  vulns = {
    list: (p?: any) => this.http.get("/vulnerabilities/", { params: p }),
    stats: () => this.http.get("/vulnerabilities/stats/"),
    remediate: (id: string, notes?: string) => this.http.post(`/vulnerabilities/${id}/remediate/`, { notes }),
    acceptRisk: (id: string, justification?: string) => this.http.post(`/vulnerabilities/${id}/accept-risk/`, { justification }),
  };
  assets = {
    list: (p?: any) => this.http.get("/assets/", { params: p }),
    create: (d: any) => this.http.post("/assets/", d),
    scan: (id: string) => this.http.post(`/assets/${id}/scan/`),
    riskSummary: () => this.http.get("/assets/risk-summary/"),
  };
  dashboard = {
    stats: () => this.http.get("/dashboard/stats/"),
    activity: () => this.http.get("/dashboard/activity/"),
    threatMap: () => this.http.get("/dashboard/threat-map/"),
    socMetrics: () => this.http.get("/dashboard/soc-metrics/"),
  };
  ai = {
    analyze: (text: string) => this.http.post("/ai/analyze/", { text }),
    summarize: (incident_id: string) => this.http.post("/ai/summarize-incident/", { incident_id }),
    prediction: () => this.http.get("/ai/threat-prediction/"),
  };
  intelligence = {
    passiveLookup: (kind: string, value: string) => this.http.get("/passive-lookup/", { params: { kind, value } }),
    forecasts: (p?: any) => this.http.get("/threat-forecasts/", { params: p }),
    refreshForecasts: () => this.http.post("/threat-forecasts/refresh/"),
    targets: (p?: any) => this.http.get("/collection-targets/", { params: p }),
    sources: (p?: any) => this.http.get("/collection-sources/", { params: p }),
    runs: (p?: any) => this.http.get("/collection-runs/", { params: p }),
    createTarget: (d: any) => this.http.post("/collection-targets/", d),
    createSource: (d: any) => this.http.post("/collection-sources/", d),
    createRun: (d: any) => this.http.post("/collection-runs/", d),
    run: (id: string) => this.http.post(`/collection-runs/${id}/run/`),
    observations: (p?: any) => this.http.get("/intelligence-observations/", { params: p }),
    campaignRadar: () => this.http.get("/campaign-radar/"),
    exportRunStix: (id: string) => this.http.get(`/collection-runs/${id}/export-stix/`),
  };
  malware = {
    scans: (p?: any) => this.http.get("/artifact-scans/", { params: p }),
    get: (id: string) => this.http.get(`/artifact-scans/${id}/`),
    submit: (file: File) => { const form = new FormData(); form.append("file", file); return this.http.post("/artifact-scans/submit/", form, { headers: { "Content-Type": "multipart/form-data" }, timeout: 120000 }); },
  };
  security = {
    reviews: (p?: any) => this.http.get("/security-reviews/", { params: p }),
    createReview: (d: any) => this.http.post("/security-reviews/", d),
    run: (id: string) => this.http.post(`/security-reviews/${id}/run/`),
    findings: (id: string) => this.http.get(`/security-reviews/${id}/findings/`),
    tools: () => this.http.get("/security-tools/"),
  };
  offensive = {
    engagements: (p?: any) => this.http.get("/engagements/", { params: p }),
    createEngagement: (d: any) => this.http.post("/engagements/", d),
    approve: (id: string) => this.http.post(`/engagements/${id}/approve/`),
    close: (id: string) => this.http.post(`/engagements/${id}/close/`),
    launch: (id: string, profile: string, target_id?: string) => this.http.post(`/engagements/${id}/launch/`, { profile, target_id }),
    launchBatch: (id: string, profile: string, target_ids?: string[]) => this.http.post(`/engagements/${id}/launch_batch/`, { profile, target_ids }),
    targets: (p?: any) => this.http.get("/engagement-targets/", { params: p }),
    createTarget: (d: any) => this.http.post("/engagement-targets/", d),
    jobs: (p?: any) => this.http.get("/assessment-jobs/", { params: p }),
    findings: () => this.http.get("/assessment-jobs/findings/"),
    events: () => this.http.get("/assessment-jobs/events/"),
    cancel: (id: string) => this.http.post(`/assessment-jobs/${id}/cancel/`),
    report: (id: string) => this.http.get(`/assessment-jobs/${id}/report/`),
    integrity: (id: string) => this.http.get(`/assessment-jobs/${id}/integrity/`),
    attackPath: (id: string) => this.http.get(`/assessment-jobs/${id}/attack_path/`),
    preflight: (id: string) => this.http.get(`/engagements/${id}/preflight/`),
    adversaryPlan: (id: string) => this.http.get(`/engagements/${id}/adversary_plan/`),
  };
  users = {
    me: () => this.http.get("/users/me/"),
    updateMe: (d: any) => this.http.patch("/users/me/", d),
  };
}

export const api = new APIClient();
export default api;
