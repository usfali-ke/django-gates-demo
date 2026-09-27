import json

import pytest
from django.core.management import call_command
from django.test import Client
from django.urls import reverse

from notes import views
from notes.models import MAX_TEXT, Note


def test_healthz(client, db):
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json() == {"status": "ok"}
    assert "no-store" in r["Cache-Control"] or "max-age=0" in r["Cache-Control"]


def test_root_redirects_to_notes(client):
    r = client.get("/")
    assert r.status_code == 302 and r["Location"] == reverse("notes:list")


@pytest.mark.parametrize("path", ["/notes/", "/notes/1/delete/"])
def test_pages_require_login(client, db, path):
    r = client.get(path)
    assert r.status_code in (302, 405)
    if r.status_code == 302:
        assert r["Location"].startswith(reverse("login"))


@pytest.mark.parametrize("method,path", [("get", "/api/notes/"), ("post", "/api/notes/"), ("delete", "/api/notes/1/")])
def test_api_requires_login(client, db, method, path):
    assert getattr(client, method)(path).status_code == 401


def test_login_flow(client, alice):
    r = client.post(reverse("login"), {"username": "alice", "password": "correct horse battery staple"})
    assert r.status_code == 302 and r["Location"] == reverse("notes:list")
    assert client.get(reverse("notes:list")).status_code == 200


def test_login_rejects_bad_password(client, alice):
    r = client.post(reverse("login"), {"username": "alice", "password": "wrong"})
    assert r.status_code == 200 and b"didn't match" in r.content


def test_logout_is_post_only(alice_client):
    assert alice_client.get(reverse("logout")).status_code == 405
    assert alice_client.post(reverse("logout")).status_code == 302
    assert alice_client.get("/api/notes/").status_code == 401


def test_create_and_list_via_page(alice_client, alice):
    r = alice_client.post(reverse("notes:list"), {"text": "  buy milk  "})
    assert r.status_code == 302
    assert list(Note.objects.values_list("text", flat=True)) == ["buy milk"]
    assert b"buy milk" in alice_client.get(reverse("notes:list")).content


@pytest.mark.parametrize("text", ["", "   ", "x" * (MAX_TEXT + 1)])
def test_page_rejects_invalid_note(alice_client, text):
    assert alice_client.post(reverse("notes:list"), {"text": text}).status_code == 400
    assert Note.objects.count() == 0


def test_note_text_is_escaped(alice_client):
    alice_client.post(reverse("notes:list"), {"text": "<script>alert(1)</script>"})
    body = alice_client.get(reverse("notes:list")).content
    assert b"<script>alert(1)</script>" not in body and b"&lt;script&gt;" in body


def test_delete_own_note(alice_client, alice):
    note = Note.objects.create(owner=alice, text="gone")
    assert alice_client.post(reverse("notes:delete", args=[note.pk])).status_code == 302
    assert not Note.objects.filter(pk=note.pk).exists()


def test_cannot_touch_another_users_note(alice_client, bob):
    """IDOR: another user's note id behaves as if it didn't exist."""
    theirs = Note.objects.create(owner=bob, text="private")
    assert alice_client.post(reverse("notes:delete", args=[theirs.pk])).status_code == 404
    assert alice_client.get(f"/api/notes/{theirs.pk}/").status_code == 404
    assert alice_client.delete(f"/api/notes/{theirs.pk}/").status_code == 404
    assert alice_client.get("/api/notes/").json() == {"notes": []}
    assert Note.objects.filter(pk=theirs.pk).exists()


def test_api_round_trip(alice_client):
    r = alice_client.post("/api/notes/", json.dumps({"text": "api"}), content_type="application/json")
    assert r.status_code == 201
    note = r.json()
    assert alice_client.get("/api/notes/").json()["notes"] == [note]
    assert alice_client.get(f"/api/notes/{note['id']}/").json() == note
    assert alice_client.delete(f"/api/notes/{note['id']}/").status_code == 204
    assert alice_client.get("/api/notes/").json() == {"notes": []}


@pytest.mark.parametrize("body", ["not json", "[]", '{"text": ""}', '{"text": 5}', json.dumps({"text": "x" * (MAX_TEXT + 1)})])
def test_api_rejects_invalid_input(alice_client, body):
    assert alice_client.post("/api/notes/", body, content_type="application/json").status_code == 400


def test_api_method_not_allowed(alice_client):
    assert alice_client.put("/api/notes/").status_code == 405
    note = alice_client.post("/api/notes/", '{"text": "a"}', content_type="application/json").json()
    assert alice_client.put(f"/api/notes/{note['id']}/").status_code == 405


def test_note_limit(alice_client, alice, monkeypatch):
    monkeypatch.setattr(views, "MAX_NOTES_PER_USER", 2)
    for i in range(2):
        alice_client.post("/api/notes/", json.dumps({"text": str(i)}), content_type="application/json")
    r = alice_client.post("/api/notes/", '{"text": "3"}', content_type="application/json")
    assert r.status_code == 409
    assert alice_client.post(reverse("notes:list"), {"text": "3"}).status_code == 400


def test_csrf_is_enforced(alice):
    c = Client(enforce_csrf_checks=True)
    c.force_login(alice)
    assert c.post("/api/notes/", '{"text": "x"}', content_type="application/json").status_code == 403
    assert c.post(reverse("notes:list"), {"text": "x"}).status_code == 403


def test_security_headers(client, db):
    r = client.get(reverse("login"))
    assert r["X-Frame-Options"] == "DENY"
    assert r["X-Content-Type-Options"] == "nosniff"
    assert r["Referrer-Policy"] == "same-origin"
    assert "default-src 'none'" in r["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in r["Content-Security-Policy"]
    assert "camera=()" in r["Permissions-Policy"]


def test_authenticated_pages_are_not_cached(alice_client):
    assert alice_client.get(reverse("notes:list"))["Cache-Control"] == "no-store"


def test_cookies_are_hardened(client, alice):
    r = client.post(reverse("login"), {"username": "alice", "password": "correct horse battery staple"})
    session = r.cookies["sessionid"]
    assert session["secure"] and session["httponly"] and session["samesite"] == "Lax"


def test_ensure_user_command(db, monkeypatch):
    monkeypatch.setenv("ENSURE_USER_PASSWORD", "a sufficiently long passphrase")
    call_command("ensure_user", "carol")
    assert Client().login(username="carol", password="a sufficiently long passphrase")


def test_ensure_user_requires_password(db, monkeypatch):
    from django.core.management.base import CommandError

    monkeypatch.delenv("ENSURE_USER_PASSWORD", raising=False)
    with pytest.raises(CommandError):
        call_command("ensure_user", "dave")


def test_settings_refuse_to_start_without_secret(monkeypatch):
    import importlib

    from django.core.exceptions import ImproperlyConfigured

    import config.settings as s

    monkeypatch.delenv("DJANGO_SECRET_KEY")
    monkeypatch.setenv("DJANGO_DEBUG", "false")
    with pytest.raises(ImproperlyConfigured):
        importlib.reload(s)
    monkeypatch.setenv("DJANGO_SECRET_KEY", "restored-" + "y" * 50)
    importlib.reload(s)
