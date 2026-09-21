"""AfricaWatch — Feed Fetchers"""
import csv, logging
import httpx
from django.utils import timezone

logger = logging.getLogger("africanwatch.fetchers")

def get_fetcher(feed):
    from africanwatch.apps.threat_intel.models import ThreatFeed
    m = {ThreatFeed.FeedType.CSV:CSVFetcher, ThreatFeed.FeedType.JSON:JSONFetcher,
         ThreatFeed.FeedType.PLAINTEXT:PlaintextFetcher, ThreatFeed.FeedType.OTX:OTXFetcher,
         ThreatFeed.FeedType.MISP:MISPFetcher, ThreatFeed.FeedType.TAXII:TAXIIFetcher}
    return m.get(feed.feed_type, PlaintextFetcher)(feed)

class BaseFetcher:
    def __init__(self, feed):
        from africanwatch.security.outbound import validate_public_url
        self.feed = feed
        validate_public_url(feed.url)
        self.client = httpx.Client(timeout=30, follow_redirects=False, trust_env=False)
    def fetch_and_import(self): raise NotImplementedError
    def _save(self, ioc_type, value, severity="medium", confidence=70,
               description="", tags=None, malware_families=None):
        from africanwatch.apps.threat_intel.models import IOC
        from africanwatch.apps.threat_intel.tasks import enrich_ioc
        if not value or not value.strip(): return None
        value = value.strip()
        now = timezone.now()
        try:
            ioc, created = IOC.objects.update_or_create(
                ioc_type=ioc_type, value_normalized=value.lower(),
                defaults={"value":value,"severity":severity,"confidence":confidence,"feed":self.feed,
                          "description":description[:1000],"tags":tags or [],
                          "malware_families":malware_families or [],
                          "first_seen":now,"last_seen":now,"is_active":True})
            if created: enrich_ioc.delay(str(ioc.id))
            return ioc
        except Exception as e:
            logger.debug(f"Save IOC error {value}: {e}")
            return None
    def _detect(self, value):
        import re
        from africanwatch.apps.threat_intel.models import IOC
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$", value): return IOC.IOCType.IP
        if re.match(r"^[a-fA-F0-9]{32}$", value): return IOC.IOCType.MD5
        if re.match(r"^[a-fA-F0-9]{40}$", value): return IOC.IOCType.SHA1
        if re.match(r"^[a-fA-F0-9]{64}$", value): return IOC.IOCType.SHA256
        if re.match(r"^https?://", value): return IOC.IOCType.URL
        if re.match(r"^CVE-\d{4}-\d{4,}$", value, re.IGNORECASE): return IOC.IOCType.CVE
        if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-.]{1,61}\.[a-zA-Z]{2,}$", value): return IOC.IOCType.DOMAIN
        return None
    def __del__(self):
        try: self.client.close()
        except: pass

class PlaintextFetcher(BaseFetcher):
    def fetch_and_import(self):
        headers = {self.feed.api_key_header: self.feed.api_key} if self.feed.api_key else {}
        resp = self.client.get(self.feed.url, headers=headers)
        resp.raise_for_status()
        count = 0
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"): continue
            t = self._detect(line)
            if t and self._save(t, line): count += 1
        return count

class CSVFetcher(BaseFetcher):
    def fetch_and_import(self):
        headers = {self.feed.api_key_header: self.feed.api_key} if self.feed.api_key else {}
        resp = self.client.get(self.feed.url, headers=headers)
        resp.raise_for_status()
        count = 0
        reader = csv.DictReader((l for l in resp.text.splitlines() if not l.startswith("#")))
        for row in reader:
            value = (row.get("url") or row.get("ip_address") or row.get("ip") or
                     row.get("domain") or row.get("md5_hash") or row.get("sha256_hash","")).strip()
            if not value: continue
            t = self._detect(value)
            if not t: continue
            threat = row.get("threat") or row.get("malware","")
            if self._save(t, value, severity="high", confidence=80, tags=[threat] if threat else [],
                          malware_families=[threat] if threat else []): count += 1
        return count

class JSONFetcher(BaseFetcher):
    def fetch_and_import(self):
        from africanwatch.apps.threat_intel.models import IOC
        headers = {self.feed.api_key_header: self.feed.api_key} if self.feed.api_key else {}
        if "abuse.ch" in self.feed.url:
            resp = self.client.post(self.feed.url, data={"query":"get_recent","selector":"100"})
        else:
            resp = self.client.get(self.feed.url, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        items = data.get("data", data.get("results", data)) if isinstance(data, dict) else data
        count = 0
        for item in items[:500]:
            if not isinstance(item, dict): continue
            families = [item["signature"].lower()] if item.get("signature") else item.get("tags",[])[:3]
            for ioc_type, value in [(IOC.IOCType.SHA256, item.get("sha256_hash","")),
                                    (IOC.IOCType.MD5, item.get("md5_hash","")),
                                    (IOC.IOCType.URL, item.get("url","")),
                                    (IOC.IOCType.DOMAIN, item.get("domain","")),
                                    (IOC.IOCType.IP, item.get("ip",""))]:
                if value and value.strip():
                    if self._save(ioc_type, value, severity="high", confidence=85, malware_families=families): count += 1
        return count

class OTXFetcher(BaseFetcher):
    def fetch_and_import(self):
        from africanwatch.apps.threat_intel.models import IOC
        if not self.feed.api_key: return 0
        resp = self.client.get("https://otx.alienvault.com/api/v1/pulses/subscribed",
            headers={"X-OTX-API-KEY": self.feed.api_key}, params={"limit":20})
        if resp.status_code != 200: return 0
        type_map = {"IPv4":IOC.IOCType.IP,"domain":IOC.IOCType.DOMAIN,"URL":IOC.IOCType.URL,
                    "FileHash-MD5":IOC.IOCType.MD5,"FileHash-SHA256":IOC.IOCType.SHA256}
        count = 0
        for pulse in resp.json().get("results",[]):
            for ind in pulse.get("indicators",[]):
                t = type_map.get(ind.get("type",""))
                v = ind.get("indicator","")
                if t and v:
                    if self._save(t, v, confidence=75, tags=pulse.get("tags",[])[:5]): count += 1
        return count

class MISPFetcher(BaseFetcher):
    def fetch_and_import(self):
        from africanwatch.apps.threat_intel.models import IOC
        if not self.feed.api_key: return 0
        headers = {"Authorization": self.feed.api_key, "Accept":"application/json", "Content-Type":"application/json"}
        resp = self.client.post(f"{self.feed.url}/attributes/restSearch",
            headers=headers, json={"limit":1000,"published":True,"to_ids":True})
        if resp.status_code != 200: return 0
        type_map = {"ip-dst":IOC.IOCType.IP,"ip-src":IOC.IOCType.IP,"domain":IOC.IOCType.DOMAIN,
                    "url":IOC.IOCType.URL,"md5":IOC.IOCType.MD5,"sha256":IOC.IOCType.SHA256}
        count = 0
        for attr in resp.json().get("response",{}).get("Attribute",[]):
            t = type_map.get(attr.get("type"))
            v = attr.get("value","")
            if t and v and self._save(t, v, confidence=80): count += 1
        return count

class TAXIIFetcher(BaseFetcher):
    def fetch_and_import(self):
        import re
        from africanwatch.apps.threat_intel.models import IOC
        try:
            from taxii2client.v21 import Server
            s = Server(self.feed.url, user=self.feed.api_key or "", password="")
            count = 0
            patterns = [(r"\[ipv4-addr:value = '([^']+)'\]",IOC.IOCType.IP),
                        (r"\[domain-name:value = '([^']+)'\]",IOC.IOCType.DOMAIN),
                        (r"\[url:value = '([^']+)'\]",IOC.IOCType.URL),
                        (r"\[file:hashes\.MD5 = '([^']+)'\]",IOC.IOCType.MD5),
                        (r"\[file:hashes\.\'SHA-256\' = '([^']+)'\]",IOC.IOCType.SHA256)]
            for coll in s.default.collections:
                for obj in coll.get_objects().get("objects",[]):
                    if obj.get("type") == "indicator":
                        for pat, t in patterns:
                            m = re.search(pat, obj.get("pattern",""), re.IGNORECASE)
                            if m and self._save(t, m.group(1), confidence=80): count += 1
            return count
        except Exception as e:
            logger.error(f"TAXII error: {e}"); return 0
