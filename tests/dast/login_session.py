"""Log in to pre-production and print `sessionid csrftoken` for the DAST
scanners. Credentials come from env (USER_A/PASSWORD_A); the CA from
REQUESTS_CA_BUNDLE. Nonzero exit if login fails, so a scan can never run
unauthenticated by accident."""

import os
import re
import sys

import requests

base = os.environ["BASE_URL"].rstrip("/")
s = requests.Session()
s.headers.update({"Origin": base, "Referer": base + "/"})
page = s.get(base + "/accounts/login/", timeout=10)
token = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', page.text)
r = s.post(
    base + "/accounts/login/",
    data={"username": os.environ["USER_A"], "password": os.environ["PASSWORD_A"], "csrfmiddlewaretoken": token and token.group(1)},
    allow_redirects=False,
    timeout=10,
)
if r.status_code != 302 or "sessionid" not in s.cookies:
    sys.exit(f"login failed: HTTP {r.status_code}")
print(s.cookies["sessionid"], s.cookies["csrftoken"])
