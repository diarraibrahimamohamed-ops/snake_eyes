from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("offensive_lab", "0002_offensive_lab_hardening")]

    operations = [
        migrations.AlterField(
            model_name="assessmentjob",
            name="profile",
            field=models.CharField(
                choices=[
                    ("dns_recon", "Reconnaissance DNS"),
                    ("web_recon", "Reconnaissance HTTP/TLS"),
                    ("port_recon", "Découverte de services"),
                    ("combined_recon", "Reconnaissance combinée"),
                    ("tls_audit", "Audit TLS"),
                    ("dns_posture", "Posture DNS"),
                    ("web_posture", "Posture Web"),
                    ("exposure_audit", "Audit d’exposition"),
                    ("adversary_recon", "Reconnaissance orientée adversaire"),
                    ("exposure_chain", "Chaîne d’exposition"),
                    ("nuclei_safe", "Nuclei — contrôles non intrusifs"),
                ],
                max_length=30,
            ),
        ),
    ]
