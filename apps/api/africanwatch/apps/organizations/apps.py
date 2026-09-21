from django.apps import AppConfig
class OrganizationsConfig(AppConfig):
    name = "africanwatch.apps.organizations"
    verbose_name = "Organisations"
    def ready(self):
        import africanwatch.apps.organizations.signals
