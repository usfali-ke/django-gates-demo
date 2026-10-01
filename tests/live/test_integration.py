"""Integration tests: the deployed app with its real parts together —
the ingress (TLS, X-Forwarded-Proto), sessions, the auth backend and the
database — through the JSON API and the pages.

    BASE_URL=... USER_A=... PASSWORD_A=... USER_B=... PASSWORD_B=... REQUESTS_CA_BUNDLE=... \
    pytest tests/live/test_integration.py
"""

import datetime as dt

from .client import (
    BASE,
    TIMEOUT,
    create,
    csrf_token,
    login,
    new_session,
    notes,
    post_login,
    unique,
)


def test_login_sets_a_secure_session(user_a):
    s = new_session()
    r = post_login(s, *user_a)
    assert r.status_code == 302 and r.headers["Location"].endswith("/notes/")
    # Secure only if Django saw the ingress's X-Forwarded-Proto: https.
    c = next(c for c in s.cookies if c.name == "sessionid")
    assert c.secure and c.has_nonstandard_attr("HttpOnly")


def test_wrong_password_is_refused(user_a):
    s = new_session()
    r = post_login(s, user_a[0], "not-the-password")
    assert r.status_code == 200 and "sessionid" not in s.cookies
    assert "didn&#x27;t match" in r.text or "didn't match" in r.text


def test_crud_via_api(a):
    text = unique("api")
    note = create(a, text)
    assert set(note) == {"id", "text", "created_at"} and note["text"] == text
    assert dt.datetime.fromisoformat(note["created_at"]).tzinfo is not None
    assert note in notes(a)
    assert (
        a.get(f"{BASE}/api/notes/{note['id']}/", timeout=TIMEOUT).json()["text"] == text
    )
    assert (
        a.delete(f"{BASE}/api/notes/{note['id']}/", timeout=TIMEOUT).status_code == 204
    )
    assert a.get(f"{BASE}/api/notes/{note['id']}/", timeout=TIMEOUT).status_code == 404


def test_api_and_page_share_the_database(a):
    """A note written through the API is on the page, and one added on the
    page is in the API: one database behind both."""
    by_api = create(a, unique("by-api"))
    assert by_api["text"] in a.get(BASE + "/notes/", timeout=TIMEOUT).text
    text = unique("by-page")
    token = csrf_token(a, "/notes/")
    assert (
        a.post(
            BASE + "/notes/",
            data={"text": text, "csrfmiddlewaretoken": token},
            timeout=TIMEOUT,
        ).status_code
        == 200
    )
    assert text in [n["text"] for n in notes(a)]


def test_notes_persist_across_sessions(user_a):
    first = login(*user_a)
    note = create(first, unique("persist"))
    second = login(*user_a)
    assert note["id"] in [n["id"] for n in notes(second)]
    second.delete(f"{BASE}/api/notes/{note['id']}/", timeout=TIMEOUT)


def test_newest_first(a):
    older, newer = create(a, unique("older")), create(a, unique("newer"))
    ids = [n["id"] for n in notes(a)]
    assert ids.index(newer["id"]) < ids.index(older["id"])


def test_text_is_trimmed_and_validated(a):
    assert create(a, "  padded  ")["text"] == "padded"
    for body in (
        {"text": ""},
        {"text": "   "},
        {"text": 5},
        {"text": "x" * 501},
        ["not", "an", "object"],
    ):
        assert (
            a.post(BASE + "/api/notes/", json=body, timeout=TIMEOUT).status_code == 400
        )
    r = a.post(
        BASE + "/api/notes/",
        data="{not json",
        headers={"Content-Type": "application/json"},
        timeout=TIMEOUT,
    )
    assert r.status_code == 400 and r.json() == {"error": "body must be JSON"}


def test_logout_ends_session(user_b):
    s = login(*user_b)
    token = csrf_token(s, "/notes/")
    r = s.post(
        BASE + "/accounts/logout/",
        data={"csrfmiddlewaretoken": token},
        allow_redirects=False,
        timeout=TIMEOUT,
    )
    assert r.status_code == 302
    assert s.get(BASE + "/api/notes/", timeout=TIMEOUT).status_code == 401
