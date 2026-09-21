"""Vulns Initial Migration"""
import uuid, django.db.models.deletion
from django.db import migrations, models
class Migration(migrations.Migration):
    initial = True
    dependencies = [("organizations","0001_initial")]
    operations = [
        migrations.CreateModel(name="Vulnerability", fields=[
            ("id",models.UUIDField(default=uuid.uuid4,editable=False,primary_key=True)),
            ("created_at",models.DateTimeField(auto_now_add=True,db_index=True)),
            ("updated_at",models.DateTimeField(auto_now=True)),
            ("asset",models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,related_name="vulnerabilities",to="organizations.asset")),
            ("cve_id",models.CharField(blank=True,db_index=True,max_length=30)),
            ("cvss_score",models.FloatField(blank=True,null=True)),
            ("severity",models.CharField(db_index=True,max_length=10)),
            ("title",models.CharField(max_length=500)),
            ("description",models.TextField()),
            ("affected_component",models.CharField(blank=True,max_length=255)),
            ("affected_version",models.CharField(blank=True,max_length=100)),
            ("fixed_version",models.CharField(blank=True,max_length=100)),
            ("status",models.CharField(db_index=True,default="open",max_length=20)),
            ("discovered_at",models.DateTimeField(auto_now_add=True)),
            ("remediated_at",models.DateTimeField(blank=True,null=True)),
            ("remediation_notes",models.TextField(blank=True)),
            ("scanner",models.CharField(blank=True,max_length=50)),
            ("raw_output",models.JSONField(blank=True,default=dict)),
            ("references",models.JSONField(blank=True,default=list)),
            ("is_exploitable",models.BooleanField(default=False)),
            ("exploit_available",models.BooleanField(default=False)),
            ("tags",models.JSONField(blank=True,default=list)),
        ], options={"ordering":["-cvss_score","-severity"]}),
        migrations.AddIndex(model_name="vulnerability",index=models.Index(fields=["asset","status"],name="vuln_asset_status")),
        migrations.CreateModel(name="ScanJob", fields=[
            ("id",models.UUIDField(default=uuid.uuid4,editable=False,primary_key=True)),
            ("created_at",models.DateTimeField(auto_now_add=True,db_index=True)),
            ("updated_at",models.DateTimeField(auto_now=True)),
            ("asset",models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,related_name="scan_jobs",to="organizations.asset")),
            ("scan_type",models.CharField(default="full",max_length=20)),
            ("status",models.CharField(default="pending",max_length=20)),
            ("started_at",models.DateTimeField(blank=True,null=True)),
            ("completed_at",models.DateTimeField(blank=True,null=True)),
            ("findings_count",models.IntegerField(default=0)),
            ("critical_count",models.IntegerField(default=0)),
            ("high_count",models.IntegerField(default=0)),
            ("medium_count",models.IntegerField(default=0)),
            ("low_count",models.IntegerField(default=0)),
            ("error_message",models.TextField(blank=True)),
            ("triggered_by",models.ForeignKey(blank=True,null=True,on_delete=django.db.models.deletion.SET_NULL,to="organizations.user")),
        ], options={"ordering":["-created_at"]}),
    ]
