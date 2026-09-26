from django.db import migrations, models
class Migration(migrations.Migration):
    dependencies=[("intelligence","0001_initial")]
    operations=[migrations.AddField(model_name="intelligenceobservation",name="actionability_score",field=models.FloatField(default=0.0))]
