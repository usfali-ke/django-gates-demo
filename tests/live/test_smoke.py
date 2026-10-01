"""Post-deployment smoke tests: read-only, no test users, no writes, so
they are safe against prod (the release runs them right after prod's
rollout; dev's automated test suite runs them too).

    BASE_URL=https://app.test REQUESTS_CA_BUNDLE=ca.crt [HTTP_URL=http://app.test] pytest tests/live/test_smoke.py
"""

import os
import re
from urllib.parse import urlsplit

import pytest
import requests

from .client import BASE, TIMEOUT, new_session

pytestmark = pytest.mark.smoke


def test_healthz():
    r = requests.get(BASE + "/healthz", timeout=TIMEOUT)
    assert r.status_code == 200 and r.json() == {"status": "ok"}
    assert "no-cache" in r.headers.get("Cache-Control", "")


def test_root_redirects_to_notes():
    r = requests.get(BASE + "/", allow_redirects=False, timeout=TIMEOUT)
    assert r.status_code == 302 and r.headers["Location"].endswith("/notes/")


def test_login_page_renders():
    r = requests.get(BASE + "/accounts/login/", timeout=TIMEOUT)
    assert r.status_code == 200
    assert (
        'name="csrfmiddlewaretoken"' in r.text
        and 'name="username"' in r.text
        and 'name="password"' in r.text
    )


def test_plain_http_redirects_to_https():
    parts = urlsplit(BASE)
    if parts.scheme != "https":
        pytest.skip("BASE_URL is not HTTPS")
    http_url = os.environ.get("HTTP_URL") or f"http://{parts.hostname}"
    r = requests.get(http_url + "/healthz", allow_redirects=False, timeout=TIMEOUT)
    assert r.status_code in (301, 302, 307, 308)
    assert r.headers["Location"].startswith("https://")


def test_transport_security_headers():
    r = requests.get(BASE + "/accounts/login/", timeout=TIMEOUT)
    assert "max-age=31536000" in r.headers.get("Strict-Transport-Security", "")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]
    csrf = next(c for c in r.cookies if c.name == "csrftoken")
    assert csrf.secure


def test_static_assets_served():
    r = requests.get(BASE + "/accounts/login/", timeout=TIMEOUT)
    href = re.search(r'href="(/static/[^"]+\.css)"', r.text).group(1)
    asset = requests.get(BASE + href, timeout=TIMEOUT)
    assert asset.status_code == 200 and asset.headers["Content-Type"].startswith(
        "text/css"
    )


def test_anonymous_access_is_refused():
    r = requests.get(BASE + "/notes/", allow_redirects=False, timeout=TIMEOUT)
    assert r.status_code == 302 and "/accounts/login/" in r.headers["Location"]
    assert requests.get(BASE + "/api/notes/", timeout=TIMEOUT).status_code == 401


def test_anonymous_write_is_refused():
    r = new_session().post(BASE + "/api/notes/", json={"text": "x"}, timeout=TIMEOUT)
    assert r.status_code in (401, 403)
