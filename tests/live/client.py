"""HTTP helpers for the suites that run against a deployed environment
(tests/live, README "Release pipeline"). Everything goes through the
environment's TLS ingress (BASE_URL) the way a browser would: CSRF token
from the form, Origin/Referer on unsafe requests, cookies in a session.
"""

import os
import re
import uuid

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


def post_login(s, user, password, next_url=None):
    token = csrf_token(s, "/accounts/login/")
    data = {"username": user, "password": password, "csrfmiddlewaretoken": token}
    if next_url is not None:
        data["next"] = next_url
    return s.post(
        BASE + "/accounts/login/", data=data, allow_redirects=False, timeout=TIMEOUT
    )


def login(user, password):
    s = new_session()
    r = post_login(s, user, password)
    assert r.status_code == 302, f"login for {user} failed: {r.status_code}"
    s.headers["X-CSRFToken"] = s.cookies["csrftoken"]
    return s


def create(s, text):
    r = s.post(BASE + "/api/notes/", json={"text": text}, timeout=TIMEOUT)
    assert r.status_code == 201, r.text
    return r.json()


def notes(s):
    r = s.get(BASE + "/api/notes/", timeout=TIMEOUT)
    assert r.status_code == 200, r.text
    return r.json()["notes"]


def unique(prefix):
    return f"{prefix}-{uuid.uuid4()}"
