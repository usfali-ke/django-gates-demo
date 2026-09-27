from django.conf import settings
from django.db import models

MAX_TEXT = 500


class Note(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="notes")
    text = models.CharField(max_length=MAX_TEXT)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]

    def as_dict(self) -> dict:
        return {"id": self.pk, "text": self.text, "created_at": self.created_at.isoformat()}
