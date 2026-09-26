from django.core.management.base import BaseCommand
from africanwatch.apps.organizations.models import Organization
from africanwatch.apps.intelligence.models import CollectionSource
SOURCES=[
 {"name":"GDELT Public News","kind":"public_api","url":"https://api.gdeltproject.org/api/v2/doc/doc","reliability":0.72,"languages":["fr","en","ar"],"countries":["ML","BF","NE","SN","CI","NG"]},
 {"name":"RDAP","kind":"rdap","url":"https://rdap.org/","reliability":0.85,"languages":["en"]},
 {"name":"Certificate Transparency — crt.sh","kind":"ct","url":"https://crt.sh/","reliability":0.82,"languages":["en"]},
 {"name":"CISA Known Exploited Vulnerabilities","kind":"public_api","url":"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json","reliability":0.92,"languages":["en"],"countries":[]},
 {"name":"Public Social Source Template — operator configured","kind":"social_public","url":"https://example.invalid/search?q={target}","reliability":0.45,"languages":["fr","en","ar"],"countries":["ML","BF","NE","SN","CI","NG"],"is_active":False,"notes":"Remplacer par une URL publique légalement accessible et autorisée; aucun compte privé."},
 {"name":"Public YouTube Search Template","kind":"social_public","url":"https://www.youtube.com/results?search_query={target}","reliability":0.40,"languages":["fr","en","ar"],"countries":["ML","BF","NE","SN","CI","NG"],"is_active":False,"notes":"Désactivé par défaut; public web uniquement."},
 {"name":"Public Reddit Search Template","kind":"social_public","url":"https://www.reddit.com/search/?q={target}","reliability":0.40,"languages":["fr","en"],"countries":[],"is_active":False,"notes":"Désactivé par défaut; public web uniquement."},
 {"name":"Public GitHub Search Template","kind":"social_public","url":"https://github.com/search?q={target}","reliability":0.55,"languages":["fr","en"],"countries":[],"is_active":False,"notes":"Désactivé par défaut; consulter uniquement du contenu public."},
 {"name":"Onion Source Template — operator allowlist","kind":"onion","url":"http://exampleonion.invalid/?q={target}","reliability":0.35,"languages":["fr","en","ar"],"countries":[],"allow_tor":True,"is_active":False,"notes":"Placeholder uniquement. Activez explicitement des hôtes .onion autorisés dans ONION_ALLOWED_HOSTS."},
]
class Command(BaseCommand):
    help="Create the baseline passive intelligence sources for every organization."
    def handle(self,*args,**kwargs):
        total=0
        for org in Organization.objects.filter(is_active=True):
            for item in SOURCES:
                CollectionSource.objects.update_or_create(organization=org,url=item["url"],defaults=item)
                total+=1
        self.stdout.write(self.style.SUCCESS(f"{total} sources d'intelligence enregistrées."))
