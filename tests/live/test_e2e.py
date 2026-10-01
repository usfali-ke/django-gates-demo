"""End-to-end tests: user journeys through the pages only, the way a
browser does them — follow links and redirects, fill in and submit the
forms the page renders (hidden fields and CSRF token included). The app
has no JavaScript, so parsing the HTML forms is what a browser would do.

    BASE_URL=... USER_A=... PASSWORD_A=... USER_B=... PASSWORD_B=... REQUESTS_CA_BUNDLE=... \
    pytest tests/live/test_e2e.py
"""

import html
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import pytest

from .client import BASE, TIMEOUT, login, new_session, notes, unique


class _Forms(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms, self.items, self._form, self._span = [], [], None, None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._form = {
                "action": a.get("action", ""),
                "method": a.get("method", "get").lower(),
                "fields": {},
                "buttons": [],
            }
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None and a.get("name"):
            self._form["fields"][a["name"]] = a.get("value", "")
        elif tag == "span":
            self._span = ""

    def handle_data(self, data):
        if self._span is not None:
            self._span += data

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None
        elif tag == "span" and self._span is not None:
            self.items.append(self._span)
            self._span = None


class Browser:
    """One user's browser: a cookie jar, the current page, its forms."""

    def __init__(self):
        self.s = new_session()
        self.page = None

    def open(self, path):
        self._load(self.s.get(urljoin(BASE + "/", path), timeout=TIMEOUT))
        return self

    def submit(self, action, **fields):
        form = next(
            (
                f
                for f in self.forms
                if urlsplit(urljoin(self.url, f["action"])).path == action
            ),
            None,
        )
        assert form, (
            f"no form posting to {action} on {self.path}: {[f['action'] for f in self.forms]}"
        )
        data = {**form["fields"], **fields}
        # Like a browser, the Origin/Referer is the page the form is on.
        r = self.s.post(
            urljoin(self.url, form["action"]),
            data=data,
            headers={"Referer": self.url},
            timeout=TIMEOUT,
        )
        self._load(r)
        return self

    def _load(self, r):
        self.page, self.url = r, r.url
        p = _Forms()
        p.feed(r.text)
        self.forms, self.items = p.forms, p.items

    @property
    def path(self):
        return urlsplit(self.url).path

    @property
    def status(self):
        return self.page.status_code

    @property
    def html(self):
        return self.page.text


def logged_in(user, password):
    b = Browser().open("/")
    assert b.path == "/accounts/login/"
    b.submit("/accounts/login/", username=user, password=password)
    assert b.status == 200 and b.path == "/notes/", (b.status, b.path)
    return b


@pytest.fixture(autouse=True)
def clean(user_a, user_b):
    yield
    for user in (user_a, user_b):
        s = login(*user)
        for n in notes(s):
            s.delete(f"{BASE}/api/notes/{n['id']}/", timeout=TIMEOUT)


def test_journey_login_add_delete_logout(user_a):
    b = Browser().open("/")
    # A deep link while logged out goes to the login page and comes back.
    assert (
        b.path == "/accounts/login/" and b.forms[-1]["fields"].get("next") == "/notes/"
    )
    b.submit("/accounts/login/", username=user_a[0], password=user_a[1])
    assert b.path == "/notes/" and "Your notes" in b.html and user_a[0] in b.html
    assert b.items == [user_a[0]] and "No notes yet." in b.html

    first, second = unique("first"), unique("second")
    b.submit("/notes/", text=first)
    b.submit("/notes/", text=second)
    assert b.path == "/notes/" and b.items[1:] == [
        second,
        first,
    ]  # newest first, after the username

    # One Delete button per note, in the list's order: the first is `second`.
    delete = [f for f in b.forms if f["action"].endswith("/delete/")][0]
    b.submit(urlsplit(urljoin(b.url, delete["action"])).path)
    assert b.path == "/notes/" and b.items[1:] == [first]

    b.submit("/accounts/logout/")
    assert b.path == "/accounts/login/"
    assert b.open("/notes/").path == "/accounts/login/"


def test_journey_empty_note_shows_an_error(user_a):
    b = logged_in(*user_a)
    b.submit("/notes/", text="   ")
    # Whitespace is stripped, so Django's required check answers first.
    assert b.status == 400 and 'class="errorlist"' in b.html
    assert b.items == [user_a[0]]


def test_journey_wrong_password_then_right(user_a):
    b = Browser().open("/accounts/login/")
    b.submit("/accounts/login/", username=user_a[0], password="not-the-password")
    assert (
        b.status == 200
        and b.path == "/accounts/login/"
        and "didn't match" in html.unescape(b.html)
    )
    b.submit("/accounts/login/", username=user_a[0], password=user_a[1])
    assert b.path == "/notes/"


def test_journey_two_users_see_only_their_own(user_a, user_b):
    alice, bob = logged_in(*user_a), logged_in(*user_b)
    mine, theirs = unique("alice"), unique("bob")
    alice.submit("/notes/", text=mine)
    bob.submit("/notes/", text=theirs)
    assert mine in alice.open("/notes/").items and theirs not in alice.items
    assert theirs in bob.open("/notes/").items and mine not in bob.items


def test_journey_markup_is_shown_as_text(user_a):
    b = logged_in(*user_a)
    text = f"<script>alert('{unique('xss')}')</script>"
    b.submit("/notes/", text=text)
    assert text in b.items  # shown as the text that was typed…
    assert text not in b.html  # …because it is escaped in the HTML
