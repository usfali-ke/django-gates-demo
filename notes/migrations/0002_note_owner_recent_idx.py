from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("notes", "0001_initial"),
    ]

    operations = [
        migrations.AddIndex(
            model_name="note",
            index=models.Index(fields=["owner", "-created_at"], name="note_owner_recent_idx"),
        ),
    ]
