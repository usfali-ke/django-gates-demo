import pytest
from django.contrib.auth import get_user_model


@pytest.fixture
def make_user(db):
    def make(username):
        return get_user_model().objects.create_user(username=username, password="correct horse battery staple")

    return make


@pytest.fixture
def alice(make_user):
    return make_user("alice")


@pytest.fixture
def bob(make_user):
    return make_user("bob")


@pytest.fixture
def alice_client(client, alice):
    client.force_login(alice)
    return client
