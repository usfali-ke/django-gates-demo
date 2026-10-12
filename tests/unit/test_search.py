"""Regression tests for notes/search.py — each one replays the attack the
original version of the feature allowed (PR #17's Hermes security review)."""

import io
import zipfile

import pytest
from django.urls import reverse

from notes.models import Note


@pytest.mark.parametrize("name", ["notes:search", "notes:export-archive", "notes:attachment"])
def test_search_endpoints_require_login(client, db, name):
    r = client.get(reverse(name))
    assert r.status_code == 302 and r["Location"].startswith(reverse("login"))


def test_search_returns_only_own_matching_notes(alice_client, alice, bob):
    Note.objects.create(owner=alice, text="buy milk")
    Note.objects.create(owner=alice, text="walk dog")
    Note.objects.create(owner=bob, text="buy milk too")
    body = alice_client.get(reverse("notes:search"), {"q": "milk"}).content.decode()
    assert "buy milk" in body and "walk dog" not in body and "too" not in body


def test_search_is_not_sql_injectable(alice_client, alice, bob):
    Note.objects.create(owner=bob, text="bob secret")
    payload = "x' UNION SELECT id, text FROM notes_note --"
    r = alice_client.get(reverse("notes:search"), {"q": payload})
    assert r.status_code == 200 and "bob secret" not in r.content.decode()


def test_search_like_wildcards_are_literal(alice_client, alice):
    Note.objects.create(owner=alice, text="plain")
    assert "plain" not in alice_client.get(reverse("notes:search"), {"q": "%"}).content.decode()


def test_search_escapes_term_and_note_text(alice_client, alice):
    Note.objects.create(owner=alice, text="<img src=x onerror=alert(1)>")
    body = alice_client.get(reverse("notes:search"), {"q": "<script>alert(1)</script>"}).content.decode()
    assert "<script>" not in body and "&lt;script&gt;" in body
    Note.objects.create(owner=alice, text="<b>x</b>")
    body = alice_client.get(reverse("notes:search"), {"q": "x"}).content.decode()
    assert "<img" not in body and "&lt;img" in body


def test_export_note_is_owner_scoped(alice_client, alice, bob):
    mine = Note.objects.create(owner=alice, text="mine")
    theirs = Note.objects.create(owner=bob, text="theirs")
    assert alice_client.get(reverse("notes:export", args=[mine.pk])).json()["text"] == "mine"
    assert alice_client.get(reverse("notes:export", args=[theirs.pk])).status_code == 404


def test_export_archive_zips_own_notes_in_memory(alice_client, alice, bob):
    Note.objects.create(owner=alice, text="a1")
    Note.objects.create(owner=bob, text="b1")
    r = alice_client.get(reverse("notes:export-archive"), {"name": "my-notes"})
    assert r.status_code == 200 and 'filename="my-notes.zip"' in r["Content-Disposition"]
    with zipfile.ZipFile(io.BytesIO(b"".join(r.streaming_content))) as zf:
        assert zf.read("notes.txt").decode() == "a1\n"


@pytest.mark.parametrize("name", ["x; touch /tmp/pwned", "$(id)", "../../evil", "a b", "x" * 65, ""])
def test_export_archive_rejects_unsafe_names(alice_client, alice, name):
    assert alice_client.get(reverse("notes:export-archive"), {"name": name}).status_code == 400


def test_attachment_serves_only_inside_own_directory(alice_client, alice, bob, settings, tmp_path):
    settings.NOTE_ATTACHMENTS_DIR = tmp_path
    (tmp_path / str(alice.pk)).mkdir()
    (tmp_path / str(alice.pk) / "a.txt").write_text("alice file")
    (tmp_path / str(bob.pk)).mkdir()
    (tmp_path / str(bob.pk) / "b.txt").write_text("bob file")
    (tmp_path / "outside.txt").write_text("outside")

    r = alice_client.get(reverse("notes:attachment"), {"file": "a.txt"})
    assert r.status_code == 200 and b"".join(r.streaming_content) == b"alice file"
    for attempt in ["../outside.txt", f"../{bob.pk}/b.txt", "/etc/passwd", str(tmp_path / "outside.txt"), "", "missing.txt"]:
        assert alice_client.get(reverse("notes:attachment"), {"file": attempt}).status_code == 404, attempt


def test_attachment_symlink_out_of_directory_is_refused(alice_client, alice, settings, tmp_path):
    settings.NOTE_ATTACHMENTS_DIR = tmp_path
    (tmp_path / "outside.txt").write_text("outside")
    (tmp_path / str(alice.pk)).mkdir()
    (tmp_path / str(alice.pk) / "link.txt").symlink_to(tmp_path / "outside.txt")
    assert alice_client.get(reverse("notes:attachment"), {"file": "link.txt"}).status_code == 404
