"""AfricaWatch — IOC Enrichers"""
import logging
import httpx
from django.conf import settings

logger = logging.getLogger("africanwatch.enrichers")

AFRICAN_CC = {"DZ","AO","BJ","BW","BF","BI","CM","CV","CF","TD","KM","CG","CD","CI","DJ","EG","GQ",
              "ER","SZ","ET","GA","GM","GH","GN","GW","KE","LS","LR","LY","MG","MW","ML","MR","MU",
              "MA","MZ","NA","NE","NG","RW","ST","SN","SC","SL","SO","ZA","SS","SD","TZ","TG","TN","UG","ZM","ZW"}


class BaseEnricher:
    def __init__(self, ioc):
        self.ioc = ioc
        self.client = httpx.Client(timeout=10.0)

    def enrich(self):
        raise NotImplementedError

    def __del__(self):
        try:
            self.client.close()
        except Exception:
            pass


class IPEnricher(BaseEnricher):
    def enrich(self):
        self._geolocate()
        self._get_asn()
        self._check_virustotal()
        self._check_shodan()
        self._flag_african()

    def _geolocate(self):
        try:
            r = self.client.get(f"http://ip-api.com/json/{self.ioc.value}",
                                params={"fields": "status,country,countryCode,lat,lon"})
            if r.status_code == 200:
                d = r.json()
                if d.get("status") == "success":
                    self.ioc.country_code = d.get("countryCode", "")
                    self.ioc.country_name = d.get("country", "")
                    self.ioc.latitude = d.get("lat")
                    self.ioc.longitude = d.get("lon")
        except Exception as e:
            logger.debug(f"Geolocate {self.ioc.value}: {e}")

    def _get_asn(self):
        try:
            from ipwhois import IPWhois
            r = IPWhois(self.ioc.value).lookup_rdap(depth=1)
            self.ioc.asn = f"AS{r.get('asn', '')}"
            self.ioc.asn_name = r.get("asn_description", "")
        except Exception as e:
            logger.debug(f"ASN {self.ioc.value}: {e}")

    def _check_virustotal(self):
        key = settings.VIRUSTOTAL_API_KEY
        if not key:
            return
        try:
            r = self.client.get(f"https://www.virustotal.com/api/v3/ip_addresses/{self.ioc.value}",
                                headers={"x-apikey": key})
            if r.status_code == 200:
                stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values()) or 1
                score = int((malicious / total) * 100)
                self.ioc.confidence = min(100, max(self.ioc.confidence, score))
                if malicious > 0:
                    self.ioc.raw_data["virustotal"] = {"malicious": malicious, "total": total}
        except Exception as e:
            logger.debug(f"VT IP {self.ioc.value}: {e}")

    def _check_shodan(self):
        key = settings.SHODAN_API_KEY
        if not key:
            return
        try:
            r = self.client.get(f"https://api.shodan.io/shodan/host/{self.ioc.value}",
                                params={"key": key})
            if r.status_code == 200:
                d = r.json()
                self.ioc.raw_data["shodan"] = {
                    "open_ports": [i.get("port") for i in d.get("data", []) if i.get("port")][:20],
                    "vulns": list(d.get("vulns", {}).keys())[:10],
                    "org": d.get("org", ""),
                    "hostnames": d.get("hostnames", [])[:5],
                }
        except Exception as e:
            logger.debug(f"Shodan {self.ioc.value}: {e}")

    def _flag_african(self):
        if self.ioc.country_code in AFRICAN_CC:
            self.ioc.is_african_threat = True
            if self.ioc.country_code not in self.ioc.african_countries_targeted:
                self.ioc.african_countries_targeted.append(self.ioc.country_code)


class DomainEnricher(BaseEnricher):
    def enrich(self):
        self._resolve_dns()
        self._whois_lookup()
        self._check_virustotal()
        self._detect_dga()
        self._detect_african_target()

    def _resolve_dns(self):
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            ips = []
            try:
                for r in resolver.resolve(self.ioc.value, "A"):
                    ips.append(str(r))
            except Exception:
                pass
            self.ioc.raw_data["dns"] = {"a_records": ips[:10]}
        except Exception as e:
            logger.debug(f"DNS {self.ioc.value}: {e}")

    def _whois_lookup(self):
        try:
            import whois
            w = whois.whois(self.ioc.value)
            self.ioc.raw_data["whois"] = {
                "registrar": str(w.registrar) if w.registrar else None,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "name_servers": list(w.name_servers)[:5] if w.name_servers else [],
            }
        except Exception as e:
            logger.debug(f"WHOIS {self.ioc.value}: {e}")

    def _check_virustotal(self):
        key = settings.VIRUSTOTAL_API_KEY
        if not key:
            return
        try:
            r = self.client.get(f"https://www.virustotal.com/api/v3/domains/{self.ioc.value}",
                                headers={"x-apikey": key})
            if r.status_code == 200:
                malicious = r.json().get("data", {}).get("attributes", {}).get(
                    "last_analysis_stats", {}).get("malicious", 0)
                if malicious > 3:
                    self.ioc.confidence = min(100, self.ioc.confidence + 20)
                    self.ioc.raw_data["virustotal"] = {"malicious": malicious}
        except Exception as e:
            logger.debug(f"VT domain {self.ioc.value}: {e}")

    def _detect_dga(self):
        domain = self.ioc.value.split(".")[0]
        vowels = sum(1 for c in domain if c in "aeiou")
        if len(domain) > 6 and vowels / max(len(domain), 1) < 0.2:
            self.ioc.tags = list(set(self.ioc.tags + ["dga-suspected"]))
            self.ioc.confidence = min(100, self.ioc.confidence + 15)

    def _detect_african_target(self):
        import re
        african_gov = [r"gov\.(ml|sn|ci|gh|ng|ke|tz|ma|tn|eg)", r"gouv\.(ml|sn|ci|bf|cm|tg|bj)"]
        for p in african_gov:
            if re.search(p, self.ioc.value):
                self.ioc.is_african_threat = True
                self.ioc.tags = list(set(self.ioc.tags + ["african-gov-targeted"]))
                if self.ioc.severity not in ["high", "critical"]:
                    self.ioc.severity = "high"
                break


class HashEnricher(BaseEnricher):
    def enrich(self):
        self._check_virustotal()
        self._check_malwarebazaar()

    def _check_virustotal(self):
        key = settings.VIRUSTOTAL_API_KEY
        if not key:
            return
        try:
            r = self.client.get(f"https://www.virustotal.com/api/v3/files/{self.ioc.value}",
                                headers={"x-apikey": key})
            if r.status_code == 200:
                attrs = r.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values()) or 1
                families = list(set([
                    res["result"].lower().split(".")[0]
                    for res in attrs.get("last_analysis_results", {}).values()
                    if res.get("category") == "malicious" and res.get("result")
                ]))[:5]
                self.ioc.malware_families = families
                self.ioc.confidence = int((malicious / total) * 100)
                self.ioc.raw_data["virustotal"] = {
                    "malicious": malicious, "total": total,
                    "file_type": attrs.get("type_description", ""),
                }
                if malicious > 5:
                    self.ioc.severity = "critical"
                elif malicious > 2:
                    self.ioc.severity = "high"
        except Exception as e:
            logger.debug(f"VT hash {self.ioc.value}: {e}")

    def _check_malwarebazaar(self):
        try:
            r = self.client.post("https://mb-api.abuse.ch/api/v1/",
                                 data={"query": "get_info", "hash": self.ioc.value}, timeout=15)
            if r.status_code == 200 and r.json().get("query_status") == "hash_found":
                info = r.json().get("data", [{}])[0]
                self.ioc.raw_data["malwarebazaar"] = {
                    "file_name": info.get("file_name"),
                    "file_type": info.get("file_type"),
                    "signature": info.get("signature"),
                    "tags": info.get("tags", []),
                }
                sig = info.get("signature", "")
                if sig:
                    sig_lower = sig.lower()
                    if sig_lower not in self.ioc.malware_families:
                        self.ioc.malware_families = (self.ioc.malware_families + [sig_lower])[:5]
        except Exception as e:
            logger.debug(f"MalwareBazaar {self.ioc.value}: {e}")
