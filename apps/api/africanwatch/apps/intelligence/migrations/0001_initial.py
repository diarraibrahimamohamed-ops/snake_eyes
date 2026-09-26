from django.db import migrations, models
import django.db.models.deletion
import uuid
import django.utils.timezone

class Migration(migrations.Migration):
    initial=True
    dependencies=[("organizations","0001_initial")]
    operations=[
        migrations.CreateModel(
            name="CollectionTarget",
            fields=[
                ("id",models.UUIDField(default=uuid.uuid4,editable=False,primary_key=True,serialize=False)),
                ("created_at",models.DateTimeField(auto_now_add=True,db_index=True)),("updated_at",models.DateTimeField(auto_now=True)),
                ("kind",models.CharField(choices=[("domain","Domaine"),("ip","Adresse IP"),("url","URL"),("email_domain","Domaine email"),("organization","Organisation"),("username_public","Identifiant public"),("email","Adresse email publique"),("phone_public","Téléphone institutionnel public"),("social_public","Profil social public"),("onion","Service Onion")],max_length=30)),
                ("value",models.CharField(max_length=500)),("label",models.CharField(blank=True,max_length=255)),("purpose",models.CharField(default="defensive_intelligence",max_length=120)),
                ("authorization_reference",models.CharField(max_length=255)),("allowed",models.BooleanField(default=False)),("is_active",models.BooleanField(default=True)),("tags",models.JSONField(blank=True,default=list)),
                ("asset",models.ForeignKey(blank=True,null=True,on_delete=django.db.models.deletion.SET_NULL,related_name="collection_targets",to="organizations.asset")),
                ("organization",models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,related_name="collection_targets",to="organizations.organization")),
            ], options={"ordering":["kind","value"]}
        ),
        migrations.AddConstraint(model_name="collectiontarget",constraint=models.UniqueConstraint(fields=("organization","kind","value"),name="uniq_collection_target_org_kind_value")),
        migrations.CreateModel(
            name="CollectionSource",
            fields=[
                ("id",models.UUIDField(default=uuid.uuid4,editable=False,primary_key=True,serialize=False)),
                ("created_at",models.DateTimeField(auto_now_add=True,db_index=True)),("updated_at",models.DateTimeField(auto_now=True)),
                ("name",models.CharField(max_length=180)),("kind",models.CharField(choices=[("news","Actualités"),("rss","RSS"),("web","Web public"),("social_public","Réseau social public"),("cert","CERT/Advisory"),("ct","Certificate Transparency"),("rdap","RDAP"),("onion","Source Onion"),("public_api","API publique")],max_length=30)),
                ("url",models.CharField(max_length=2000)),("reliability",models.FloatField(default=0.5)),("languages",models.JSONField(blank=True,default=list)),("countries",models.JSONField(blank=True,default=list)),("allow_tor",models.BooleanField(default=False)),("is_active",models.BooleanField(default=True)),("notes",models.TextField(blank=True)),
                ("organization",models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,related_name="collection_sources",to="organizations.organization")),
            ], options={"ordering":["name"]}
        ),
        migrations.AddConstraint(model_name="collectionsource",constraint=models.UniqueConstraint(fields=("organization","url"),name="uniq_collection_source_org_url")),
        migrations.CreateModel(
            name="CollectionRun",
            fields=[
                ("id",models.UUIDField(default=uuid.uuid4,editable=False,primary_key=True,serialize=False)),
                ("created_at",models.DateTimeField(auto_now_add=True,db_index=True)),("updated_at",models.DateTimeField(auto_now=True)),
                ("status",models.CharField(choices=[("queued","En attente"),("running","En cours"),("completed","Terminée"),("failed","Échec"),("blocked","Bloquée")],default="queued",max_length=20)),
                ("mode",models.CharField(default="passive",max_length=30)),("started_at",models.DateTimeField(blank=True,null=True)),("completed_at",models.DateTimeField(blank=True,null=True)),("result_summary",models.JSONField(blank=True,default=dict)),("evidence_root_hash",models.CharField(blank=True,max_length=64)),("error_message",models.TextField(blank=True)),
                ("organization",models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,related_name="collection_runs",to="organizations.organization")),
                ("requested_by",models.ForeignKey(blank=True,null=True,on_delete=django.db.models.deletion.SET_NULL,to="organizations.user")),
                ("target",models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,related_name="runs",to="intelligence.collectiontarget")),
            ], options={"ordering":["-created_at"]}
        ),
        migrations.CreateModel(
            name="IntelligenceObservation",
            fields=[
                ("id",models.UUIDField(default=uuid.uuid4,editable=False,primary_key=True,serialize=False)),
                ("created_at",models.DateTimeField(auto_now_add=True,db_index=True)),("updated_at",models.DateTimeField(auto_now=True)),
                ("source_label",models.CharField(blank=True,max_length=255)),("source_url",models.URLField(blank=True)),("title",models.CharField(blank=True,max_length=500)),("content",models.TextField()),
                ("language",models.CharField(blank=True,max_length=12)),("published_at",models.DateTimeField(blank=True,null=True)),("retrieved_at",models.DateTimeField(default=django.utils.timezone.now)),("content_sha256",models.CharField(db_index=True,max_length=64)),
                ("evidence_grade",models.CharField(default="C",max_length=2)),("source_reliability",models.FloatField(default=0.5)),("confidence",models.FloatField(default=0.5)),("relevance",models.FloatField(default=0.0)),("classification",models.JSONField(blank=True,default=dict)),("entities",models.JSONField(blank=True,default=dict)),("iocs",models.JSONField(blank=True,default=list)),("provenance",models.JSONField(blank=True,default=dict)),("tlp",models.CharField(default="green",max_length=10)),("first_seen",models.DateTimeField(default=django.utils.timezone.now)),("last_seen",models.DateTimeField(default=django.utils.timezone.now)),("corroboration_count",models.PositiveIntegerField(default=0)),("is_verified",models.BooleanField(default=False)),
                ("organization",models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,related_name="intelligence_observations",to="organizations.organization")),
                ("run",models.ForeignKey(blank=True,null=True,on_delete=django.db.models.deletion.SET_NULL,related_name="observations",to="intelligence.collectionrun")),
                ("source",models.ForeignKey(blank=True,null=True,on_delete=django.db.models.deletion.SET_NULL,related_name="observations",to="intelligence.collectionsource")),
            ], options={"ordering":["-retrieved_at"]}
        ),
        migrations.AddConstraint(model_name="intelligenceobservation",constraint=models.UniqueConstraint(fields=("organization","content_sha256","source_url"),name="uniq_intel_observation_content_source")),
        migrations.CreateModel(
            name="IntelligenceRelation",
            fields=[
                ("id",models.UUIDField(default=uuid.uuid4,editable=False,primary_key=True,serialize=False)),("created_at",models.DateTimeField(auto_now_add=True,db_index=True)),("updated_at",models.DateTimeField(auto_now=True)),
                ("relation_type",models.CharField(max_length=60)),("weight",models.FloatField(default=0.5)),("evidence",models.JSONField(blank=True,default=dict)),
                ("left",models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,related_name="relations_left",to="intelligence.intelligenceobservation")),
                ("organization",models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,related_name="intelligence_relations",to="organizations.organization")),
                ("right",models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,related_name="relations_right",to="intelligence.intelligenceobservation")),
            ]
        ),
        migrations.CreateModel(
            name="ThreatForecast",
            fields=[
                ("id",models.UUIDField(default=uuid.uuid4,editable=False,primary_key=True,serialize=False)),("created_at",models.DateTimeField(auto_now_add=True,db_index=True)),("updated_at",models.DateTimeField(auto_now=True)),
                ("horizon_hours",models.PositiveIntegerField(default=168)),("generated_at",models.DateTimeField(default=django.utils.timezone.now)),("signal_type",models.CharField(max_length=80)),("level",models.CharField(max_length=20)),("score",models.FloatField(default=0.0)),("confidence",models.FloatField(default=0.0)),("basis",models.JSONField(blank=True,default=dict)),("statement",models.TextField()),("model",models.CharField(default="deterministic-threat-trend-v1",max_length=80)),
                ("organization",models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,related_name="threat_forecasts",to="organizations.organization")),
            ], options={"ordering":["-generated_at"]}
        ),
    ]
