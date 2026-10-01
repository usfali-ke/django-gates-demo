"""Regression tests: behaviour that was fixed or decided once and must not
come back, each against the deployed environment (the setting, middleware
or proxy that causes it may differ there from the unit tests' settings).

    BASE_URL=... USER_A=... PASSWORD_A=... USER_B=... PASSWORD_B=... REQUESTS_CA_BUNDLE=... \
    pytest tests/live/test_regression.py
"""

import re

import requests

from .client import BASE, TIMEOUT, create, csrf_token, notes, unique


def test_static_files_send_no_cors_header():
    """dfd7c95: WhiteNoise's default `Access-Control-Allow-Origin: *` on
    /static/ (ZAP 10098 Cross-Domain Misconfiguration)."""
    page = requests.get(BASE + "/accounts/login/", timeout=TIMEOUT)
    href = re.search(r'href="(/static/[^"]+\.css)"', page.text).group(1)
    asset = requests.get(
        BASE + href, headers={"Origin": "https://evil.example"}, timeout=TIMEOUT
    )
    assert asset.status_code == 200
    assert "Access-Control-Allow-Origin" not in asset.headers


def test_api_does_not_coerce_non_strings(a):
    """A form field coerces 5 or [..] to "5"; the API must refuse them."""
    for text in (5, 5.5, True, None, ["x"], {"x": 1}):
        r = a.post(BASE + "/api/notes/", json={"text": text}, timeout=TIMEOUT)
        assert r.status_code == 400 and r.json() == {
            "error": "text must be a string"
        }, text
    assert not [n for n in notes(a) if n["text"] in ("5", "5.5", "True", "None")]


def test_per_user_note_limit(b):
    """MAX_NOTES_PER_USER (200): one account can't fill the database."""
    have = len(notes(b))
    for i in range(200 - have):
        create(b, f"limit {i}")
    r = b.post(BASE + "/api/notes/", json={"text": "one too many"}, timeout=TIMEOUT)
    assert r.status_code == 409 and r.json() == {"error": "note limit reached"}
    token = csrf_token(b, "/notes/")
    page = b.post(
        BASE + "/notes/",
        data={"text": "one too many", "csrfmiddlewaretoken": token},
        timeout=TIMEOUT,
    )
    assert page.status_code == 400 and "at most 200 notes" in page.text
    for n in notes(b):
        b.delete(f"{BASE}/api/notes/{n['id']}/", timeout=TIMEOUT)
    assert notes(b) == []


def test_unsafe_actions_need_post(a):
    note = create(a, unique("get-delete"))
    assert (
        a.get(
            f"{BASE}/notes/{note['id']}/delete/", allow_redirects=False, timeout=TIMEOUT
        ).status_code
        == 405
    )
    assert (
        a.get(
            BASE + "/accounts/logout/", allow_redirects=False, timeout=TIMEOUT
        ).status_code
        == 405
    )
    assert note["id"] in [n["id"] for n in notes(a)]
    assert (
        a.get(BASE + "/api/notes/", timeout=TIMEOUT).status_code == 200
    )  # still logged in


def test_api_method_allow_lists(a):
    note = create(a, unique("methods"))
    r = a.put(BASE + "/api/notes/", json={"text": "x"}, timeout=TIMEOUT)
    assert r.status_code == 405 and set(
        r.headers["Allow"].replace(" ", "").split(",")
    ) == {"GET", "POST"}
    r = a.patch(f"{BASE}/api/notes/{note['id']}/", json={"text": "x"}, timeout=TIMEOUT)
    assert r.status_code == 405 and set(
        r.headers["Allow"].replace(" ", "").split(",")
    ) == {"GET", "DELETE"}
    # Anonymous POST: CSRF refuses it (403) before require_GET would (405).
    assert requests.post(BASE + "/healthz", timeout=TIMEOUT).status_code in (403, 405)


def test_oversized_body_rejected(a):
    """DATA_UPLOAD_MAX_MEMORY_SIZE (64 KiB): the app takes small notes only."""
    r = a.post(BASE + "/api/notes/", json={"text": "x" * (70 * 1024)}, timeout=TIMEOUT)
    assert r.status_code == 400


def test_logged_in_user_skips_login_page(a):
    r = a.get(BASE + "/accounts/login/", allow_redirects=False, timeout=TIMEOUT)
    assert r.status_code == 302 and r.headers["Location"].endswith("/notes/")


def test_per_user_pages_are_not_cached(a):
    for path in ("/notes/", "/api/notes/"):
        assert (
            a.get(BASE + path, timeout=TIMEOUT).headers.get("Cache-Control")
            == "no-store"
        ), path
    page = a.get(BASE + "/notes/", timeout=TIMEOUT)
    href = re.search(r'href="(/static/[^"]+\.css)"', page.text).group(1)
    assert (
        a.get(BASE + href, timeout=TIMEOUT).headers.get("Cache-Control") != "no-store"
    )
