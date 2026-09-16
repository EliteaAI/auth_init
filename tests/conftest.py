"""Shared fixtures. Mirrors the runtime shape of auth_init's login processor."""
import pathlib
import sys
import types

import pytest

TESTS_DIR = pathlib.Path(__file__).resolve().parent
PLUGIN_ROOT = TESTS_DIR.parent

sys.path.insert(0, str(TESTS_DIR))

from fixtures import helpers  # noqa: E402  pylint: disable=C0413

PYLON_LOG = helpers.install_pylon_stubs()


@pytest.fixture(scope="session")
def plugin_root() -> pathlib.Path:
    return PLUGIN_ROOT


@pytest.fixture(scope="session")
def processor(plugin_root: pathlib.Path):
    """The rpc/processor.py module under test."""
    return helpers.import_plugin_module(plugin_root, "rpc.processor")


@pytest.fixture
def pylon_log():
    """The stub Pylon log, cleared per test."""
    PYLON_LOG.warnings.clear()
    PYLON_LOG.exceptions.clear()
    return PYLON_LOG


class AuthCore:
    """Records the auth_core RPCs the processor calls.

    Failures are configured per RPC name, which is how a missing or older
    auth_core - one without ensure_system_token - is expressed.
    """

    def __init__(self, user_id=1, errors=None):
        self.user_id = user_id
        self.errors = errors or {}
        self.calls = []

    def _record(self, name, *args, **kwargs):
        self.calls.append((name, args, kwargs))
        error = self.errors.get(name)
        if error is not None:
            raise error

    def called(self, name):
        return [call for call in self.calls if call[0] == name]

    def get_user(self, email=None, **kwargs):
        self._record("get_user", email=email, **kwargs)
        return {"id": self.user_id}

    def add_user(self, email, name=None):
        self._record("add_user", email, name)
        return self.user_id

    def add_user_provider(self, user_id, provider_id):
        self._record("add_user_provider", user_id, provider_id)

    def add_user_group(self, user_id, group_id):
        self._record("add_user_group", user_id, group_id)

    def ensure_system_token(self, user_id):
        self._record("ensure_system_token", user_id)
        return "encoded-token"

    def update_user(self, id_=None, **kwargs):
        self._record("update_user", id_=id_, **kwargs)
        return id_, "Existing Name"

    def get_user_roles(self, user_id):
        self._record("get_user_roles", user_id)
        return ["viewer"]

    def assign_user_to_role(self, user_id, role):
        self._record("assign_user_to_role", user_id, role)


@pytest.fixture
def auth_core():
    return AuthCore()


@pytest.fixture
def events():
    fired = []

    def fire_event(name, payload):
        fired.append((name, payload))

    return types.SimpleNamespace(fired=fired, fire_event=fire_event)


@pytest.fixture
def subject(processor, auth_core, events):
    """The login processor bound to a recording auth_core."""
    sys.modules["tools"].auth_core = auth_core
    processor.auth_core = auth_core

    instance = processor.RPC()
    instance.descriptor = types.SimpleNamespace(config={})
    instance.context = types.SimpleNamespace(event_manager=events)

    return instance


@pytest.fixture
def auth_ctx():
    """What the auth provider hands the processor for a known user."""
    return {
        "user_id": 1,
        "provider_attr": {
            "nameid": "user@example.com",
            "attributes": {"email": "user@example.com", "name": "A User"},
        },
    }


def pytest_collection_modifyitems(items):
    for item in items:
        if "/unit/" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        elif "/integration/" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
