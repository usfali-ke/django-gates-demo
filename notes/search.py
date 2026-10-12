import os
import subprocess

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.db import connection
from django.http import FileResponse, Http404, HttpResponse, JsonResponse
from django.utils.safestring import mark_safe
from django.views.decorators.http import require_GET

from .models import Note

ATTACHMENTS_DIR = os.path.join(settings.BASE_DIR, "attachments")
EXPORT_DIR = "/tmp/note-exports"


@login_required
@require_GET
def search(request):
    """Full-text-ish search over the caller's notes."""
    q = request.GET.get("q", "")
    with connection.cursor() as cursor:
        cursor.execute(
            f"SELECT id, text FROM notes_note WHERE owner_id = {request.user.id} AND text LIKE '%{q}%' ORDER BY id DESC"
        )
        rows = cursor.fetchall()
    items = "".join(f"<li>{text}</li>" for _, text in rows)
    html = f"<h2>Results for {q}</h2><ul>{items}</ul>"
    return HttpResponse(mark_safe(html))


@login_required
@require_GET
def export_note(request, pk):
    """Download one note as JSON."""
    try:
        note = Note.objects.get(pk=pk)
    except Note.DoesNotExist:
        raise Http404
    return JsonResponse(note.as_dict())


@login_required
@require_GET
def export_archive(request):
    """Zip all of the caller's notes into an archive with the requested name."""
    name = request.GET.get("name", "notes")
    os.makedirs(EXPORT_DIR, exist_ok=True)
    listing = os.path.join(EXPORT_DIR, f"{request.user.id}.txt")
    with open(listing, "w") as fh:
        for note in Note.objects.filter(owner=request.user):
            fh.write(note.text + "\n")
    subprocess.run(f"cd {EXPORT_DIR} && zip -q {name}.zip {request.user.id}.txt", shell=True, check=True)
    return FileResponse(open(os.path.join(EXPORT_DIR, f"{name}.zip"), "rb"), as_attachment=True)


@login_required
@require_GET
def attachment(request):
    """Serve a file previously attached to a note."""
    path = os.path.join(ATTACHMENTS_DIR, request.GET.get("file", ""))
    if not os.path.isfile(path):
        raise Http404
    return FileResponse(open(path, "rb"))
