import io
import re
import zipfile
from pathlib import Path

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, Http404, HttpResponse, HttpResponseBadRequest, JsonResponse
from django.shortcuts import get_object_or_404
from django.utils.html import format_html, format_html_join
from django.views.decorators.http import require_GET

from .models import Note

# Archive names become a download filename only; nothing is written to disk.
ARCHIVE_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
MAX_RESULTS = 50


def _attachments_root(user) -> Path:
    # Per-user directory, so one account can never reach another's files.
    base = Path(getattr(settings, "NOTE_ATTACHMENTS_DIR", settings.BASE_DIR / "attachments"))
    return (base / str(user.pk)).resolve()


@login_required
@require_GET
def search(request):
    """Search the caller's notes. ORM (parameterized; LIKE wildcards in the
    term are escaped by icontains) and auto-escaped HTML for both the term
    and the note text."""
    q = request.GET.get("q", "").strip()[:200]
    notes = Note.objects.filter(owner=request.user, text__icontains=q).order_by("-id")[:MAX_RESULTS]
    items = format_html_join("", "<li>{}</li>", ((n.text,) for n in notes))
    return HttpResponse(format_html("<h2>Results for {}</h2><ul>{}</ul>", q, items))


@login_required
@require_GET
def export_note(request, pk):
    """Download one of the caller's notes as JSON. Another user's id is a
    404 (same as the API), so ids can't be probed."""
    return JsonResponse(get_object_or_404(Note, pk=pk, owner=request.user).as_dict())


@login_required
@require_GET
def export_archive(request):
    """Zip the caller's notes in memory: no shell, no temp files, and the
    requested name is validated before it reaches the download filename."""
    name = request.GET.get("name", "notes")
    if not ARCHIVE_NAME.match(name):
        return HttpResponseBadRequest("name may contain only letters, digits, '-' and '_' (max 64)")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("notes.txt", "".join(n.text + "\n" for n in Note.objects.filter(owner=request.user)))
    buf.seek(0)
    return FileResponse(buf, as_attachment=True, filename=f"{name}.zip", content_type="application/zip")


@login_required
@require_GET
def attachment(request):
    """Download one of the caller's attachments. The resolved path must stay
    inside the caller's own directory: '..', absolute paths and symlinks
    pointing out of it are all a 404. Always a download, never rendered: an
    uploaded .html/.svg served inline would be stored XSS on this origin."""
    root = _attachments_root(request.user)
    requested = request.GET.get("file", "")
    if not requested:
        raise Http404
    path = (root / requested).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise Http404
    response = FileResponse(path.open("rb"), as_attachment=True, filename=path.name, content_type="application/octet-stream")
    response["X-Content-Type-Options"] = "nosniff"
    return response
