
import json
import logging

from functools import wraps

from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.core.exceptions import RequestDataTooBig
from django.db import connection, transaction
from django.http import (
    HttpResponse,
    HttpResponseNotAllowed,
    JsonResponse,
)
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from .forms import NoteForm
from .models import Note


logger = logging.getLogger(__name__)

MAX_NOTES_PER_USER = 200
MAX_JSON_BODY_BYTES = 16 * 1024
DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 50


# --------------------------------------------------
# Common response helpers
# --------------------------------------------------

def api_error(message, status=400, **extra):
    return JsonResponse(
        {
            "error": message,
            **extra,
        },
        status=status,
    )


def api_login_required(view):
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return api_error(
                "Authentication required",
                status=401,
            )

        return view(request, *args, **kwargs)

    return wrapped


def parse_positive_int(value, default, maximum):
    if value is None:
        return default

    try:
        # Reject negatives, zero and non-digit input.
        if not value.isascii() or not value.isdecimal():
            return None

        parsed = int(value)

        if not 1 <= parsed <= maximum:
            return None

        return parsed

    except (ValueError, TypeError):
        return None


def parse_json_body(request):
    content_type = request.content_type

    if content_type != "application/json":
        return None, api_error(
            "Content-Type must be application/json",
            status=415,
        )

    content_length = request.META.get("CONTENT_LENGTH")

    if content_length:
        try:
            if int(content_length) > MAX_JSON_BODY_BYTES:
                return None, api_error(
                    "Request body too large",
                    status=413,
                )
        except (ValueError, TypeError):
            return None, api_error(
                "Invalid Content-Length",
                status=400,
            )

    try:
        # Django may reject the body through its global
        # DATA_UPLOAD_MAX_MEMORY_SIZE setting.
        raw_body = request.body

        if len(raw_body) > MAX_JSON_BODY_BYTES:
            return None, api_error(
                "Request body too large",
                status=413,
            )

        payload = json.loads(raw_body)

    except RequestDataTooBig:
        return None, api_error(
            "Request body too large",
            status=413,
        )

    except (ValueError, UnicodeDecodeError):
        return None, api_error(
            "Malformed JSON request body",
            status=400,
        )

    if not isinstance(payload, dict):
        return None, api_error(
            "JSON body must be an object",
            status=400,
        )

    if set(payload) != {"text"}:
        return None, api_error(
            "Only the 'text' field is allowed",
            status=400,
        )

    if not isinstance(payload["text"], str):
        return None, api_error(
            "Text must be a string",
            status=400,
        )

    return payload, None


# --------------------------------------------------
# Health endpoints
# --------------------------------------------------

@require_GET
@never_cache
def healthz(request):
    """
    Lightweight liveness probe.

    Does not require database availability.
    """
    return JsonResponse({"status": "ok"})


@require_GET
@never_cache
def readyz(request):
    """
    Readiness probe.

    Checks whether the application can communicate
    with its database.
    """
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()

    except Exception:
        logger.exception("Database readiness check failed")

        return JsonResponse(
            {"status": "unavailable"},
            status=503,
        )

    return JsonResponse({"status": "ok"})


# --------------------------------------------------
# Note creation with atomic quota enforcement
# --------------------------------------------------

class NoteLimitReached(Exception):
    pass


def create_note(user, form):
    """
    Serialize note creation per user to enforce
    MAX_NOTES_PER_USER under concurrent requests.

    Requires a database with effective row-level locks,
    such as PostgreSQL or MySQL/InnoDB.
    """
    UserModel = get_user_model()

    with transaction.atomic():
        # Lock the owner's row, not existing notes.
        # This also works when the user has zero notes.
        UserModel._default_manager.select_for_update().get(
            pk=user.pk
        )

        current_count = Note.objects.filter(
            owner_id=user.pk
        ).count()

        if current_count >= MAX_NOTES_PER_USER:
            raise NoteLimitReached

        note = form.save(commit=False)
        note.owner_id = user.pk
        note.save()

        return note


# --------------------------------------------------
# HTML views
# --------------------------------------------------

@login_required
@csrf_protect
@never_cache
@require_http_methods(["GET", "POST"])
def note_list(request):
    if request.method == "POST":
        form = NoteForm(request.POST)

        if form.is_valid():
            try:
                create_note(request.user, form)

            except NoteLimitReached:
                form.add_error(
                    None,
                    f"You can keep at most "
                    f"{MAX_NOTES_PER_USER} notes.",
                )

            else:
                return redirect("notes:list")

    else:
        form = NoteForm()

    notes = (
        Note.objects
        .filter(owner=request.user)
        .order_by("-pk")[:MAX_NOTES_PER_USER]
    )

    return render(
        request,
        "notes/list.html",
        {
            "form": form,
            "notes": notes,
        },
        status=400 if form.errors else 200,
    )


@login_required
@csrf_protect
@never_cache
@require_POST
def note_delete(request, pk):
    note = get_object_or_404(
        Note,
        pk=pk,
        owner=request.user,
    )

    note.delete()

    return redirect("notes:list")


# --------------------------------------------------
# JSON API
# --------------------------------------------------

@api_login_required
@csrf_protect
@never_cache
@require_http_methods(["GET", "POST"])
def api_notes(request):

    if request.method == "GET":
        page = parse_positive_int(
            request.GET.get("page"),
            default=1,
            maximum=100000,
        )

        page_size = parse_positive_int(
            request.GET.get("page_size"),
            default=DEFAULT_PAGE_SIZE,
            maximum=MAX_PAGE_SIZE,
        )

        if page is None or page_size is None:
            return api_error(
                "Invalid pagination parameters",
                status=400,
            )

        queryset = Note.objects.filter(
            owner=request.user
        ).order_by("-pk")

        total = queryset.count()
        start = (page - 1) * page_size
        end = start + page_size

        notes = queryset[start:end]

        return JsonResponse({
            "notes": [note.as_dict() for note in notes],
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total": total,
                "has_next": end < total,
            },
        })

    payload, error = parse_json_body(request)

    if error is not None:
        return error

    form = NoteForm({
        "text": payload["text"],
    })

    if not form.is_valid():
        return api_error(
            "Invalid note",
            status=400,
            fields=form.errors.get_json_data(),
        )

    try:
        note = create_note(request.user, form)

    except NoteLimitReached:
        return api_error(
            "Note limit reached",
            status=409,
        )

    return JsonResponse(
        note.as_dict(),
        status=201,
    )


@api_login_required
@csrf_protect
@never_cache
@require_http_methods(["GET", "DELETE"])
def api_note_detail(request, pk):
    note = get_object_or_404(
        Note,
        pk=pk,
        owner=request.user,
    )

    if request.method == "GET":
        return JsonResponse(note.as_dict())

    note.delete()

    return HttpResponse(status=204)
