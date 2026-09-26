from django.db import migrations, models

class Migration(migrations.Migration):
    dependencies = [("intelligence", "0002_actionability")]
    operations = [
        migrations.AlterField(model_name="collectionsource", name="url", field=models.CharField(max_length=2000)),
    ]
