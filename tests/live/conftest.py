import os

import pytest

from .client import BASE, TIMEOUT, login, notes


@pytest.fixture(scope="session")
def user_a():
    return os.environ["USER_A"], os.environ["PASSWORD_A"]


@pytest.fixture(scope="session")
def user_b():
    return os.environ["USER_B"], os.environ["PASSWORD_B"]


@pytest.fixture(scope="module")
def a(user_a):
    s = login(*user_a)
    yield s
    _clean(s)


@pytest.fixture(scope="module")
def b(user_b):
    s = login(*user_b)
    yield s
    _clean(s)


def _clean(s):
    # The test users live as long as the pod: leave them as found.
    for n in notes(s):
        s.delete(f"{BASE}/api/notes/{n['id']}/", timeout=TIMEOUT)
