"""Authenticated security tests (DAST, with two real users): what an
unauthenticated scanner (nuclei) can't reach — object-level authorization
across accounts, the session's life cycle, CSRF, redirects after login,
user enumeration, injection, and what responses give away. OWASP Top 10
2021 category in each docstring.

    BASE_URL=... USER_A=... PASSWORD_A=... USER_B=... PASSWORD_B=... REQUESTS_CA_BUNDLE=... \
    pytest tests/live/test_security.py
"""

import html
import re

import pytest
import requests

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


def test_idor_across_users(a, b):
    """A01: B can neither see nor delete A's note, by page or by API, and
    another user's id is a 404 (ids can't be probed), not a 403."""
    note = create(a, unique("private"))
    assert b.get(f"{BASE}/api/notes/{note['id']}/", timeout=TIMEOUT).status_code == 404
    assert (
        b.delete(f"{BASE}/api/notes/{note['id']}/", timeout=TIMEOUT).status_code == 404
    )
    token = csrf_token(b, "/notes/")
    r = b.post(
        f"{BASE}/notes/{note['id']}/delete/",
        data={"csrfmiddlewaretoken": token},
        timeout=TIMEOUT,
    )
    assert r.status_code == 404
    assert note["id"] not in [n["id"] for n in notes(b)]
    assert note["text"] not in b.get(BASE + "/notes/", timeout=TIMEOUT).text
    assert a.get(f"{BASE}/api/notes/{note['id']}/", timeout=TIMEOUT).status_code == 200


def test_csrf_required(a):
    """A01: a write needs the CSRF token and a same-origin Origin."""
    r = a.post(
        BASE + "/api/notes/",
        json={"text": "x"},
        headers={"X-CSRFToken": "wrong"},
        timeout=TIMEOUT,
    )
    assert r.status_code == 403
    r = a.post(
        BASE + "/api/notes/",
        json={"text": "x"},
        headers={"Origin": "https://evil.example"},
        timeout=TIMEOUT,
    )
    assert r.status_code == 403
    token = csrf_token(a, "/notes/")
    r = a.post(
        BASE + "/notes/",
        data={"text": "x", "csrfmiddlewaretoken": token},
        headers={"Origin": "https://evil.example", "Referer": "https://evil.example/"},
        timeout=TIMEOUT,
    )
    assert r.status_code == 403


@pytest.mark.parametrize(
    "target",
    [
        "https://evil.example/",
        "//evil.example/",
        "/\\evil.example/",
        "https:evil.example",
    ],
)
def test_no_open_redirect_after_login(user_a, target):
    """A01: `next` can only send the user somewhere on this site."""
    r = post_login(new_session(), *user_a, next_url=target)
    assert r.status_code == 302
    location = r.headers["Location"]
    assert "evil.example" not in location and location.endswith("/notes/")


def test_session_fixation(user_a):
    """A07: a session id planted before login is not the one after it."""
    planted = "attackerchosensessionid0000000000"
    s = new_session()
    s.cookies.set("sessionid", planted)
    r = post_login(s, *user_a)
    assert r.status_code == 302
    assert r.cookies.get("sessionid") not in (None, planted)
    assert (
        requests.get(
            BASE + "/api/notes/", cookies={"sessionid": planted}, timeout=TIMEOUT
        ).status_code
        == 401
    )


def test_logout_invalidates_the_session_server_side(user_b):
    """A07: a copied session cookie stops working once its user logs out."""
    s = login(*user_b)
    stolen = s.cookies["sessionid"]
    token = csrf_token(s, "/notes/")
    s.post(
        BASE + "/accounts/logout/", data={"csrfmiddlewaretoken": token}, timeout=TIMEOUT
    )
    replay = requests.get(
        BASE + "/api/notes/", cookies={"sessionid": stolen}, timeout=TIMEOUT
    )
    assert replay.status_code == 401


def test_no_user_enumeration(user_a):
    """A07: an unknown user and a wrong password look the same."""
    wrong_session, unknown_session = new_session(), new_session()
    wrong = post_login(wrong_session, user_a[0], "not-the-password-1")
    unknown = post_login(unknown_session, unique("nobody"), "not-the-password-1")
    assert wrong.status_code == unknown.status_code == 200
    error = re.compile(r'<p class="error">([^<]*)</p>')
    assert error.findall(wrong.text) == error.findall(unknown.text) and error.findall(
        wrong.text
    )
    assert (
        "sessionid" not in wrong_session.cookies
        and "sessionid" not in unknown_session.cookies
    )
    assert "not-the-password-1" not in wrong.text + unknown.text


def test_cookie_flags(a):
    """A05: both cookies Secure, HttpOnly, SameSite=Lax."""
    for name in ("sessionid", "csrftoken"):
        c = next(c for c in a.cookies if c.name == name)
        assert c.secure, name
        assert c.has_nonstandard_attr("HttpOnly"), name
        assert (c.get_nonstandard_attr("SameSite") or "").lower() == "lax", name


@pytest.mark.parametrize("path", ["/notes/", "/api/notes/"])
def test_security_headers_when_logged_in(a, path):
    """A05: the hardening headers are on authenticated responses too."""
    h = a.get(BASE + path, timeout=TIMEOUT).headers
    assert "max-age=31536000" in h.get("Strict-Transport-Security", "")
    assert (
        "default-src 'none'" in h.get("Content-Security-Policy", "")
        and "frame-ancestors 'none'" in h["Content-Security-Policy"]
    )
    assert h.get("X-Content-Type-Options") == "nosniff"
    assert h.get("X-Frame-Options") == "DENY"
    assert h.get("Referrer-Policy") == "same-origin"
    assert h.get("Cross-Origin-Opener-Policy") == "same-origin"
    assert h.get("Cross-Origin-Resource-Policy") == "same-origin"
    assert "camera=()" in h.get("Permissions-Policy", "")


def test_api_sends_no_cors_headers(a):
    """A05: no other origin may read the API with the user's cookies."""
    r = a.get(
        BASE + "/api/notes/",
        headers={"Origin": "https://evil.example"},
        timeout=TIMEOUT,
    )
    assert (
        "Access-Control-Allow-Origin" not in r.headers
        and "Access-Control-Allow-Credentials" not in r.headers
    )
    pre = requests.options(
        BASE + "/api/notes/",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "DELETE",
        },
        timeout=TIMEOUT,
    )
    assert "Access-Control-Allow-Origin" not in pre.headers


@pytest.mark.parametrize(
    "path",
    [
        "/admin/",
        "/admin/login/",
        "/.env",
        "/static/../config/settings.py",
        "/static/%2e%2e/config/settings.py",
        "/no-such-page",
    ],
)
def test_nothing_extra_exposed(path):
    """A05: no admin site, no files outside static, and DEBUG is off (a
    404 is the plain page, not Django's URL list or a traceback)."""
    r = requests.get(BASE + path, allow_redirects=False, timeout=TIMEOUT)
    assert r.status_code == 404, (path, r.status_code)
    for leak in (
        "Traceback",
        "DEBUG = True",
        "URLconf",
        "DJANGO_SECRET_KEY",
        "SECRET_KEY",
    ):
        assert leak not in r.text, (path, leak)


def test_trace_is_refused():
    """A05: no TRACE (cross-site tracing)."""
    assert requests.request(
        "TRACE", BASE + "/healthz", timeout=TIMEOUT
    ).status_code in (400, 405, 501)


@pytest.mark.parametrize(
    "payload",
    [
        "' OR '1'='1' --",
        "1; DROP TABLE notes_note;--",
        '" onmouseover="alert(1)',
        "{{7*7}}",
        "${7*7}",
        "../../etc/passwd",
    ],
)
def test_injection_payloads_are_just_text(a, payload):
    """A03: stored and shown verbatim, never interpreted (SQL, template, markup)."""
    note = create(a, payload)
    assert note["text"] == payload
    assert (
        a.get(f"{BASE}/api/notes/{note['id']}/", timeout=TIMEOUT).json()["text"]
        == payload
    )
    page = a.get(BASE + "/notes/", timeout=TIMEOUT).text
    assert f"<span>{html.escape(payload)}</span>" in page
    assert "<span>49</span>" not in page
    assert notes(a)  # the table is still there


def test_markup_is_escaped(a):
    """A03: stored XSS through the page form."""
    text = f"<img src=x onerror=alert('{unique('xss')}')>"
    token = csrf_token(a, "/notes/")
    r = a.post(
        BASE + "/notes/",
        data={"text": text, "csrfmiddlewaretoken": token},
        timeout=TIMEOUT,
    )
    assert r.status_code == 200
    assert text not in r.text and "&lt;img src=x" in r.text


@pytest.mark.parametrize(
    "path",
    ["/api/notes/1%20OR%201=1/", "/api/notes/-1/", "/api/notes/99999999999999999999/"],
)
def test_id_tampering(a, path):
    """A03/A01: a malformed or out-of-range id is a plain 404."""
    assert a.get(BASE + path, timeout=TIMEOUT).status_code == 404
