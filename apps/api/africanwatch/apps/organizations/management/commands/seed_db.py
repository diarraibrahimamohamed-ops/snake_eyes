from django.core.management.base import BaseCommand
from django.utils import timezone
import random

class Command(BaseCommand):
    help = "Charge les données de démonstration AfricaWatch"
    def handle(self, *args, **options):
        self._orgs(); self._actors(); self._iocs(); self._alerts(); self._osint_sources()
        self.stdout.write(self.style.SUCCESS("Données de démo chargées"))

    def _orgs(self):
        from africanwatch.apps.organizations.models import Organization, User
        for d in [{"name":"CERT-ML","slug":"cert-ml","org_type":"cert","country":"MLI","country_name":"Mali","contact_email":"cert@mali.gov.ml"},{"name":"CERT-SN","slug":"cert-sn","org_type":"cert","country":"SEN","country_name":"Sénégal","contact_email":"cert@sn.gouv.sn"},{"name":"Bank of Ghana Cyber","slug":"bog-cyber","org_type":"bank","country":"GHA","country_name":"Ghana","contact_email":"security@bog.gov.gh"}]:
            org, c = Organization.objects.get_or_create(slug=d["slug"],defaults=d)
            if c:
                User.objects.get_or_create(email=f"admin@{d['slug']}.aw",defaults={"first_name":"Admin","last_name":org.name,"organization":org,"role":"org_admin","is_active":True})
                self.stdout.write(f"  Organisation: {org.name}")

    def _actors(self):
        from africanwatch.apps.threat_intel.models import ThreatActor
        for d in [{"name":"SilverFox","motivation":"financial","sophistication":"advanced","targets_africa":True,"target_countries":["NGR","GHA","SEN","MLI"],"target_sectors":["banking","mobile_money"],"description":"Groupe APT financièrement motivé ciblant les banques africaines","known_tools":["Emotet","TrickBot"],"is_active":True},{"name":"SaharaGhost","motivation":"espionage","sophistication":"expert","targets_africa":True,"target_countries":["MLI","NER","TCD","BFA"],"target_sectors":["government","military"],"description":"APT d'espionnage ciblant les gouvernements du Sahel","is_active":True}]:
            _, c = ThreatActor.objects.get_or_create(name=d["name"],defaults=d)
            if c: self.stdout.write(f"  Acteur: {d['name']}")

    def _iocs(self):
        from africanwatch.apps.threat_intel.models import IOC, ThreatFeed
        feed, _ = ThreatFeed.objects.get_or_create(name="AfricaWatch Demo Feed",defaults={"feed_type":"custom_api","url":"https://demo.africanwatch.africa","is_african_specific":True,"status":"active","tlp_level":"green"})
        now = timezone.now()
        for d in [{"ioc_type":"ip","value":"197.234.45.123","severity":"critical","country_code":"NG","is_african_threat":True,"confidence":90,"malware_families":["emotet"]},{"ioc_type":"domain","value":"mobile-money-ng.xyz","severity":"critical","is_african_threat":True,"tags":["phishing","mobile-money"],"confidence":95},{"ioc_type":"url","value":"http://gov-ml.phishing-site.tk/login","severity":"critical","is_african_threat":True,"confidence":98},{"ioc_type":"sha256","value":"a3f9c84b2e1d5f8a9c2b4e6f8a1d3c5e7b9f2a4c6e8b0d2f4a6c8e0b2d4f6a8","severity":"high","malware_families":["ransomware"],"confidence":85},{"ioc_type":"cve","value":"CVE-2024-3094","severity":"critical","description":"XZ Utils backdoor","confidence":100}]:
            d.update({"feed":feed,"first_seen":now-timezone.timedelta(days=random.randint(1,30)),"last_seen":now,"value_normalized":d["value"].lower(),"country_name":"","tags":d.get("tags",[]),"malware_families":d.get("malware_families",[])})
            _, c = IOC.objects.get_or_create(ioc_type=d["ioc_type"],value_normalized=d["value"].lower(),defaults=d)
            if c: self.stdout.write(f"  IOC: {d['value']}")

    def _alerts(self):
        from africanwatch.apps.soc.models import Alert
        from africanwatch.apps.organizations.models import Organization
        org = Organization.objects.first()
        if not org: return
        for d in [{"title":"Connexion suspecte depuis IP malveillante","severity":"critical","source":"threat_intel","src_ip":"197.234.45.123","status":"new"},{"title":"Tentative brute-force SSH","severity":"high","source":"wazuh","src_ip":"41.206.134.56","status":"new"},{"title":"Trafic DNS suspect — C2 possible","severity":"high","source":"zeek","status":"new"}]:
            d.update({"organization":org,"description":d["title"],"raw_log":{"demo":True}})
            Alert.objects.get_or_create(organization=org,title=d["title"],defaults=d)
        self.stdout.write("  Alertes créées")

    def _osint_sources(self):
        from africanwatch.apps.osint.models import OSINTSource
        for d in [{"name":"Jeune Afrique Tech","source_type":"news_site","url":"https://www.jeuneafrique.com/economie/tech-telecoms/","countries":["MLI","SEN","CIV"],"languages":["fr"],"is_african_source":True},{"name":"Cyber Africa Forum RSS","source_type":"rss","url":"https://cyberafricaforum.com/feed/","countries":[],"languages":["fr"],"is_african_source":True},{"name":"Twitter CyberAfrica","source_type":"twitter","handle":"@CyberAfrica","url":"https://twitter.com","countries":[],"languages":["fr","en"],"is_african_source":True}]:
            _, c = OSINTSource.objects.get_or_create(name=d["name"],defaults=d)
            if c: self.stdout.write(f"  Source OSINT: {d['name']}")
