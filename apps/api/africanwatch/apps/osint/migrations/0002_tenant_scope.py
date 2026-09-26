from django.db import migrations, models
import django.db.models.deletion

def copy_source_org_to_events(apps, schema_editor):
    Source = apps.get_model("osint", "OSINTSource")
    Event = apps.get_model("osint", "OSINTEvent")
    for source in Source.objects.exclude(organization_id=None).iterator():
        Event.objects.filter(source_id=source.id, organization_id=None).update(organization_id=source.organization_id)

class Migration(migrations.Migration):
    dependencies = [("osint", "0001_initial"), ("organizations", "0001_initial")]
    operations = [
        migrations.AddField(
            model_name="osintsource", name="organization",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name="osint_sources", to="organizations.organization"),
        ),
        migrations.AddField(
            model_name="osintevent", name="organization",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name="osint_events", to="organizations.organization"),
        ),
        migrations.RunPython(copy_source_org_to_events, migrations.RunPython.noop),
    ]
