"""The API contract added with pagination and strict JSON parsing (PR #18):
page/page_size bounds, 415/413/400 rejections, the single allowed field,
and the liveness/readiness split (healthz never touches the database)."""

import json
from unittest import mock

import pytest

from notes import views
from notes.models import Note


def test_pagination_pages_and_reports_has_next(alice_client, alice):
    for i in range(3):
        Note.objects.create(owner=alice, text=f"n{i}")
    first = alice_client.get("/api/notes/", {"page_size": 2}).json()
    assert [n["text"] for n in first["notes"]] == ["n2", "n1"]  # newest first
    assert first["pagination"] == {"page": 1, "page_size": 2, "total": 3, "has_next": True}
    second = alice_client.get("/api/notes/", {"page": 2, "page_size": 2}).json()
    assert [n["text"] for n in second["notes"]] == ["n0"] and second["pagination"]["has_next"] is False


@pytest.mark.parametrize("params", [{"page": "0"}, {"page": "-1"}, {"page": "x"}, {"page": "１"}, {"page_size": str(views.MAX_PAGE_SIZE + 1)}, {"page_size": "0"}])
def test_pagination_rejects_out_of_range_or_non_digit(alice_client, params):
    r = alice_client.get("/api/notes/", params)
    assert r.status_code == 400 and r.json() == {"error": "Invalid pagination parameters"}


def test_pagination_only_lists_own_notes(alice_client, alice, bob):
    Note.objects.create(owner=bob, text="bob's")
    assert alice_client.get("/api/notes/").json()["pagination"]["total"] == 0


def test_post_requires_json_content_type(alice_client):
    r = alice_client.post("/api/notes/", {"text": "x"})  # form-encoded
    assert r.status_code == 415


def test_post_rejects_oversized_bodies(alice_client):
    big = json.dumps({"text": "x" * (views.MAX_JSON_BODY_BYTES + 10)})
    assert alice_client.post("/api/notes/", big, content_type="application/json").status_code == 413


def test_post_rejects_a_bad_declared_length(alice_client):
    r = alice_client.post("/api/notes/", "{}", content_type="application/json", CONTENT_LENGTH="abc")
    assert r.status_code == 400 and r.json()["error"] == "Invalid Content-Length"


@pytest.mark.parametrize("body", ['{"text": "x", "owner": 1}', "{}", '{"other": "x"}'])
def test_post_allows_only_the_text_field(alice_client, body):
    r = alice_client.post("/api/notes/", body, content_type="application/json")
    assert r.status_code == 400 and r.json()["error"] == "Only the 'text' field is allowed"


def test_post_enforces_the_per_user_limit(alice_client, alice, monkeypatch):
    monkeypatch.setattr(views, "MAX_NOTES_PER_USER", 1)
    Note.objects.create(owner=alice, text="only")
    r = alice_client.post("/api/notes/", json.dumps({"text": "two"}), content_type="application/json")
    assert r.status_code == 409 and Note.objects.filter(owner=alice).count() == 1


def test_healthz_is_liveness_only(client, db, django_assert_num_queries):
    with django_assert_num_queries(0):
        assert client.get("/healthz").json() == {"status": "ok"}


def test_readyz_checks_the_database(client, db):
    r = client.get("/readyz")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_readyz_reports_an_unavailable_database(client, db):
    # Patched for the request only — pytest-django's teardown needs the
    # real cursor.
    with mock.patch.object(views.connection, "cursor", side_effect=RuntimeError("db down")):
        r = client.get("/readyz")
    assert r.status_code == 503 and r.json() == {"status": "unavailable"}
