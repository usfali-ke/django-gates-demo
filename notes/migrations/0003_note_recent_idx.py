from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("notes", "0002_note_owner_recent_idx"),
    ]

    operations = [
        migrations.AddIndex(
            model_name="note",
            index=models.Index(fields=["-created_at"], name="note_recent_idx"),
        ),
    ]
