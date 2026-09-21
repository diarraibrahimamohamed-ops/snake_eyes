from django.core.management.base import BaseCommand
class Command(BaseCommand):
    help = "Initialise les flux publics de threat intelligence"
    def handle(self, *args, **options):
        from africanwatch.apps.threat_intel.tasks import bootstrap_feeds
        bootstrap_feeds()
        self.stdout.write(self.style.SUCCESS("Flux initialisés"))
