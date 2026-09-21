from django.core.management.base import BaseCommand
from africanwatch.apps.security_lab.models import ToolDefinition
from africanwatch.apps.security_lab.management_seed import TOOL_CATALOG


class Command(BaseCommand):
    help = "Seed the controlled security assessment tool catalog."

    def handle(self, *args, **options):
        for item in TOOL_CATALOG:
            ToolDefinition.objects.update_or_create(slug=item["slug"], defaults=item)
        self.stdout.write(self.style.SUCCESS(f"{len(TOOL_CATALOG)} outils enregistrés."))
