"""Functional, integration and regression tests against a running deployment
(pre-production: the image behind the TLS proxy in the pipeline).

    BASE_URL=https://app.test USER_A=... PASSWORD_A=... USER_B=... PASSWORD_B=... \
    REQUESTS_CA_BUNDLE=caddy-root.crt [HTTP_URL=http://app.test] pytest tests/functional

Two real users, so object-level authorization is exercised across
accounts, not just by unit tests.

`-m smoke` runs only the read-only checks that need no test users and
write nothing — what the release runs against prod after a rollout
(BASE_URL alone).
"""

import os
import re
import uuid
from urllib.parse import urlsplit

import pytest
import requests

BASE = os.environ["BASE_URL"].rstrip("/")
TIMEOUT = 10


def new_session():
    s = requests.Session()
    # Django checks Origin (and Referer) on HTTPS POSTs.
    s.headers.update({"Origin": BASE, "Referer": BASE + "/"})
    return s


def csrf_token(s, path):
    r = s.get(BASE + path, timeout=TIMEOUT)
    r.raise_for_status()
    m = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', r.text)
    assert m, f"no CSRF token on {path}"
    return m.group(1)


def login(user, password):
    s = new_session()
    token = csrf_token(s, "/accounts/login/")
    r = s.post(
        BASE + "/accounts/login/",
        data={"username": user, "password": password, "csrfmiddlewaretoken": token},
        allow_redirects=False,
        timeout=TIMEOUT,
    )
    assert r.status_code == 302, f"login for {user} failed: {r.status_code}"
    s.headers["X-CSRFToken"] = s.cookies["csrftoken"]
    return s


@pytest.fixture(scope="module")
def a():
    return login(os.environ["USER_A"], os.environ["PASSWORD_A"])


@pytest.fixture(scope="module")
def b():
    return login(os.environ["USER_B"], os.environ["PASSWORD_B"])


def create(s, text):
    r = s.post(BASE + "/api/notes/", json={"text": text}, timeout=TIMEOUT)
    assert r.status_code == 201, r.text
    return r.json()


@pytest.mark.smoke
def test_healthz():
    r = requests.get(BASE + "/healthz", timeout=TIMEOUT)
    assert r.status_code == 200 and r.json() == {"status": "ok"}


@pytest.mark.smoke
def test_plain_http_redirects_to_https():
    parts = urlsplit(BASE)
    if parts.scheme != "https":
        pytest.skip("BASE_URL is not HTTPS")
    http_url = os.environ.get("HTTP_URL") or f"http://{parts.hostname}"
    r = requests.get(http_url + "/healthz", allow_redirects=False, timeout=TIMEOUT)
    assert r.status_code in (301, 302, 307, 308)
    assert r.headers["Location"].startswith("https://")


@pytest.mark.smoke
def test_transport_security_headers():
    r = requests.get(BASE + "/accounts/login/", timeout=TIMEOUT)
    assert "max-age=31536000" in r.headers.get("Strict-Transport-Security", "")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]
    csrf = next(c for c in r.cookies if c.name == "csrftoken")
    assert csrf.secure


@pytest.mark.smoke
def test_static_assets_served():
    r = requests.get(BASE + "/accounts/login/", timeout=TIMEOUT)
    href = re.search(r'href="(/static/[^"]+\.css)"', r.text).group(1)
    asset = requests.get(BASE + href, timeout=TIMEOUT)
    assert asset.status_code == 200
    # regression: WhiteNoise's default `Access-Control-Allow-Origin: *` (ZAP 10098)
    assert "Access-Control-Allow-Origin" not in asset.headers


@pytest.mark.smoke
def test_anonymous_access_is_refused():
    r = requests.get(BASE + "/notes/", allow_redirects=False, timeout=TIMEOUT)
    assert r.status_code == 302 and "/accounts/login/" in r.headers["Location"]
    assert requests.get(BASE + "/api/notes/", timeout=TIMEOUT).status_code == 401


@pytest.mark.smoke
def test_anonymous_write_is_refused():
    r = new_session().post(BASE + "/api/notes/", json={"text": "x"}, timeout=TIMEOUT)
    assert r.status_code in (401, 403)


def test_wrong_password_is_refused():
    s = new_session()
    token = csrf_token(s, "/accounts/login/")
    r = s.post(
        BASE + "/accounts/login/",
        data={"username": os.environ["USER_A"], "password": "not-the-password", "csrfmiddlewaretoken": token},
        allow_redirects=False,
        timeout=TIMEOUT,
    )
    assert r.status_code == 200 and "sessionid" not in s.cookies


def test_session_cookie_flags(a):
    c = next(c for c in a.cookies if c.name == "sessionid")
    assert c.secure and c.has_nonstandard_attr("HttpOnly")


def test_crud_via_api(a):
    text = f"api-{uuid.uuid4()}"
    note = create(a, text)
    assert note in a.get(BASE + "/api/notes/", timeout=TIMEOUT).json()["notes"]
    assert a.get(f"{BASE}/api/notes/{note['id']}/", timeout=TIMEOUT).json()["text"] == text
    assert a.delete(f"{BASE}/api/notes/{note['id']}/", timeout=TIMEOUT).status_code == 204
    assert a.get(f"{BASE}/api/notes/{note['id']}/", timeout=TIMEOUT).status_code == 404


def test_crud_via_page_and_escaping(a):
    text = f"<img src=x onerror=alert('{uuid.uuid4()}')>"
    token = csrf_token(a, "/notes/")
    r = a.post(BASE + "/notes/", data={"text": text, "csrfmiddlewaretoken": token}, timeout=TIMEOUT)
    assert r.status_code == 200  # followed the redirect back to the list
    assert text not in r.text and "&lt;img src=x" in r.text


def test_invalid_input_rejected(a):
    for body in ({"text": ""}, {"text": 5}, {"text": "x" * 501}, ["not", "an", "object"]):
        assert a.post(BASE + "/api/notes/", json=body, timeout=TIMEOUT).status_code == 400


def test_csrf_required(a):
    r = a.post(BASE + "/api/notes/", json={"text": "x"}, headers={"X-CSRFToken": "wrong"}, timeout=TIMEOUT)
    assert r.status_code == 403
    r = a.post(BASE + "/api/notes/", json={"text": "x"}, headers={"Origin": "https://evil.example"}, timeout=TIMEOUT)
    assert r.status_code == 403


def test_idor_across_users(a, b):
    """B can neither see nor delete A's note, by page or by API."""
    note = create(a, f"private-{uuid.uuid4()}")
    assert b.get(f"{BASE}/api/notes/{note['id']}/", timeout=TIMEOUT).status_code == 404
    assert b.delete(f"{BASE}/api/notes/{note['id']}/", timeout=TIMEOUT).status_code == 404
    token = csrf_token(b, "/notes/")
    r = b.post(f"{BASE}/notes/{note['id']}/delete/", data={"csrfmiddlewaretoken": token}, timeout=TIMEOUT)
    assert r.status_code == 404
    assert note["id"] not in [n["id"] for n in b.get(BASE + "/api/notes/", timeout=TIMEOUT).json()["notes"]]
    assert note["text"] not in b.get(BASE + "/notes/", timeout=TIMEOUT).text
    assert a.get(f"{BASE}/api/notes/{note['id']}/", timeout=TIMEOUT).status_code == 200


def test_logout_ends_session():
    s = login(os.environ["USER_B"], os.environ["PASSWORD_B"])
    token = csrf_token(s, "/notes/")
    s.post(BASE + "/accounts/logout/", data={"csrfmiddlewaretoken": token}, timeout=TIMEOUT)
    assert s.get(BASE + "/api/notes/", timeout=TIMEOUT).status_code == 401
