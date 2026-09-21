export type Severity="info"|"low"|"medium"|"high"|"critical";
export interface IOC { id:string; ioc_type:string; value:string; severity:Severity; confidence:number; is_african_threat:boolean; first_seen:string; last_seen:string; is_active:boolean; description:string; tags:string[]; malware_families:string[]; country_code:string; country_name:string; created_at:string; }
export interface Alert { id:string; title:string; severity:Severity; status:string; source:string; src_ip?:string; created_at:string; }
export interface Incident { id:string; title:string; severity:Severity; status:string; incident_type:string; detected_at:string; systems_affected:number; data_compromised:boolean; timeline:any[]; alert_count:number; }
export interface Vulnerability { id:string; asset_name:string; cve_id:string; cvss_score?:number; severity:Severity; title:string; status:string; is_exploitable:boolean; }
export interface OSINTEvent { id:string; source_name:string; content:string; content_translated:string; language_detected:string; threat_relevance_score:number; is_threat_relevant:boolean; sentiment:string; url:string; }
export interface PaginatedResponse<T> { count:number; total_pages:number; current_page:number; next?:string; previous?:string; results:T[]; }
