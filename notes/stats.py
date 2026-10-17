"""Daily note counts for the signed-in owner.

A parameterized raw query over the (owner, created_at) index added in
migration 0002: the owner id and the cutoff are bound, so nothing from the
request reaches the statement text.
"""

from datetime import timedelta

from django.contrib.auth.decorators import login_required
from django.db import connection
from django.http import HttpResponseBadRequest, JsonResponse
from django.utils import timezone
from django.views.decorators.http import require_GET

DEFAULT_DAYS = 30
MAX_DAYS = 90


@login_required
@require_GET
def daily_counts(request):
    """How many notes the caller added per day over the last N days."""
    try:
        days = int(request.GET.get("days", DEFAULT_DAYS))
    except (TypeError, ValueError):
        return HttpResponseBadRequest("days must be an integer")

    if not 1 <= days <= MAX_DAYS:
        return HttpResponseBadRequest(f"days must be between 1 and {MAX_DAYS}")

    cutoff = timezone.now() - timedelta(days=days)

    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT DATE(created_at) AS day, COUNT(*)"
            " FROM notes_note"
            " WHERE owner_id = %s AND created_at >= %s"
            " GROUP BY DATE(created_at) ORDER BY DATE(created_at) DESC"
            " LIMIT %s",
            [request.user.pk, cutoff, days + 1],
        )
        rows = cursor.fetchall()

    return JsonResponse(
        {"days": days, "counts": [{"day": day, "count": count} for day, count in rows]}
    )
