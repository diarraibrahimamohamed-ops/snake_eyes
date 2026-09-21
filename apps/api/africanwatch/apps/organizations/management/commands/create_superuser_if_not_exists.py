from django.core.management.base import BaseCommand
class Command(BaseCommand):
    help = "Crée un superuser s il n existe pas"
    def add_arguments(self, parser):
        parser.add_argument("--email", required=True)
        parser.add_argument("--password", required=True)
    def handle(self, *args, **options):
        from africanwatch.apps.organizations.models import User
        email, password = options["email"], options["password"]
        if not User.objects.filter(email=email).exists():
            User.objects.create_superuser(email=email, password=password, first_name="Super", last_name="Admin")
            self.stdout.write(self.style.SUCCESS(f"Superuser créé: {email}"))
        else:
            self.stdout.write(f"Superuser existe: {email}")
