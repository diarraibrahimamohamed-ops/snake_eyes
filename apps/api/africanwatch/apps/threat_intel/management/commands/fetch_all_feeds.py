from django.core.management.base import BaseCommand
class Command(BaseCommand):
    help = "Lance la récupération de tous les flux"
    def handle(self, *args, **options):
        from africanwatch.apps.threat_intel.tasks import fetch_all_feeds
        fetch_all_feeds()
        self.stdout.write(self.style.SUCCESS("Récupération lancée"))
