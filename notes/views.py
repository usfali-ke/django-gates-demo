import json

from django.contrib.auth.decorators import login_required
from django.db import connection
from django.http import HttpResponse, HttpResponseNotAllowed, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from .forms import NoteForm
from .models import Note

# Per-user cap, so one account can't fill the database.
MAX_NOTES_PER_USER = 200


@require_GET
@never_cache
def healthz(request):
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1")
    return JsonResponse({"status": "ok"})


def _at_limit(user) -> bool:
    return Note.objects.filter(owner=user).count() >= MAX_NOTES_PER_USER


@login_required
@require_http_methods(["GET", "POST"])
def note_list(request):
    form = NoteForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        if _at_limit(request.user):
            form.add_error(None, f"You can keep at most {MAX_NOTES_PER_USER} notes.")
        else:
            form.instance.owner = request.user
            form.save()
            return redirect("notes:list")
    notes = Note.objects.filter(owner=request.user)
    return render(request, "notes/list.html", {"form": form, "notes": notes}, status=400 if form.errors else 200)


@login_required
@require_POST
def note_delete(request, pk):
    # Scoped to the owner: another user's id is a 404, not a 403, so ids
    # can't be probed.
    get_object_or_404(Note, pk=pk, owner=request.user).delete()
    return redirect("notes:list")


def _api_login_required(view):
    def wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({"error": "authentication required"}, status=401)
        return view(request, *args, **kwargs)

    return wrapped


@_api_login_required
def api_notes(request):
    if request.method == "GET":
        return JsonResponse({"notes": [n.as_dict() for n in Note.objects.filter(owner=request.user)]})
    if request.method != "POST":
        return HttpResponseNotAllowed(["GET", "POST"])
    try:
        body = json.loads(request.body)
    except ValueError:
        return JsonResponse({"error": "body must be JSON"}, status=400)
    text = body.get("text") if isinstance(body, dict) else None
    if not isinstance(text, str):  # a form would coerce 5 or [..] to a string
        return JsonResponse({"error": "text must be a string"}, status=400)
    form = NoteForm({"text": text})
    if not form.is_valid():
        return JsonResponse({"error": "invalid note", "fields": form.errors.get_json_data()}, status=400)
    if _at_limit(request.user):
        return JsonResponse({"error": "note limit reached"}, status=409)
    form.instance.owner = request.user
    return JsonResponse(form.save().as_dict(), status=201)


@_api_login_required
def api_note_detail(request, pk):
    note = get_object_or_404(Note, pk=pk, owner=request.user)
    if request.method == "GET":
        return JsonResponse(note.as_dict())
    if request.method == "DELETE":
        note.delete()
        return HttpResponse(status=204)
    return HttpResponseNotAllowed(["GET", "DELETE"])
