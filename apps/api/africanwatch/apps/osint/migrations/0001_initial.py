"""OSINT Initial Migration"""
import uuid, django.db.models.deletion
from django.db import migrations, models
class Migration(migrations.Migration):
    initial = True
    dependencies = [("threat_intel","0001_initial")]
    operations = [
        migrations.CreateModel(name="OSINTSource", fields=[
            ("id",models.UUIDField(default=uuid.uuid4,editable=False,primary_key=True)),
            ("created_at",models.DateTimeField(auto_now_add=True,db_index=True)),
            ("updated_at",models.DateTimeField(auto_now=True)),
            ("name",models.CharField(max_length=255)),
            ("source_type",models.CharField(max_length=20)),
            ("url",models.URLField(blank=True)),
            ("handle",models.CharField(max_length=255,blank=True)),
            ("description",models.TextField(blank=True)),
            ("countries",models.JSONField(default=list,blank=True)),
            ("languages",models.JSONField(default=list,blank=True)),
            ("is_african_source",models.BooleanField(default=True)),
            ("is_active",models.BooleanField(default=True)),
            ("crawl_frequency_minutes",models.IntegerField(default=60)),
            ("last_crawled_at",models.DateTimeField(null=True,blank=True)),
            ("last_event_count",models.IntegerField(default=0)),
            ("error_count",models.IntegerField(default=0)),
            ("keywords",models.JSONField(default=list,blank=True)),
            ("exclude_keywords",models.JSONField(default=list,blank=True)),
        ], options={"ordering":["name"]}),
        migrations.CreateModel(name="OSINTEvent", fields=[
            ("id",models.UUIDField(default=uuid.uuid4,editable=False,primary_key=True)),
            ("created_at",models.DateTimeField(auto_now_add=True,db_index=True)),
            ("updated_at",models.DateTimeField(auto_now=True)),
            ("source",models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,related_name="events",to="osint.osintsource")),
            ("content",models.TextField()),
            ("content_translated",models.TextField(blank=True)),
            ("language_detected",models.CharField(max_length=10,blank=True)),
            ("url",models.URLField(blank=True)),
            ("author",models.CharField(max_length=255,blank=True)),
            ("published_at",models.DateTimeField(null=True,blank=True)),
            ("sentiment",models.CharField(max_length=20,default="neutral")),
            ("threat_relevance_score",models.FloatField(default=0.0)),
            ("is_threat_relevant",models.BooleanField(default=False,db_index=True)),
            ("entities_persons",models.JSONField(default=list,blank=True)),
            ("entities_organizations",models.JSONField(default=list,blank=True)),
            ("entities_locations",models.JSONField(default=list,blank=True)),
            ("entities_iocs",models.JSONField(default=list,blank=True)),
            ("keywords_matched",models.JSONField(default=list,blank=True)),
            ("related_iocs",models.ManyToManyField(blank=True,to="threat_intel.ioc")),
            ("raw_data",models.JSONField(default=dict,blank=True)),
            ("is_processed",models.BooleanField(default=False,db_index=True)),
            ("is_verified",models.BooleanField(default=False)),
        ], options={"ordering":["-published_at"]}),
    ]
