"""The login -> provider identity link must be written when run the way Pylon runs it (C-1009, #6941).

Pylon binds only the @web.rpc/@web.method functions onto the Module. A handler that
reaches a helper through ``self`` therefore fails at runtime with AttributeError - which
the surrounding best-effort block swallows and logs, so the login still succeeds but
the link is never written. Direct ``RPC()`` instances hide this (they have every
method), so these tests drive the handler through an object that has only what Pylon binds.
"""
import sys
import types

from fixtures import helpers

NAMEID = "oidc|tenant|subject-1"
STABLE_REF = "oidc-stable-ref-1"
EMAIL = "user@example.com"


class LinkingAuthCore:
    """auth_core where provider links really exist, so the test can see them written."""

    def __init__(self, user_id=7):
        self.user_id = user_id
        self.links = {}  # provider reference -> user id
        self.emails = {user_id: EMAIL}

    def get_user(self, user_id=None, email=None):
        if user_id is not None:
            return {"id": user_id, "email": self.emails[user_id]}
        for known_id, known_email in self.emails.items():
            if known_email == email:
                return {"id": known_id, "email": known_email}
        raise LookupError(email)

    def get_user_from_provider(self, provider_ref):
        if provider_ref not in self.links:
            raise LookupError(provider_ref)
        return {"id": self.links[provider_ref]}

    def add_user_provider(self, user_id, provider_ref):
        self.links[provider_ref] = user_id

    def add_user(self, email, name=None):
        self.emails[self.user_id] = email
        return self.user_id

    def add_user_group(self, user_id, group_id):
        pass

    def ensure_system_token(self, user_id):
        return "token"

    def update_user(self, id_=None, **kwargs):
        if "email" in kwargs:
            self.emails[id_] = kwargs["email"]
        return id_, "A User"

    def get_user_roles(self, user_id):
        return ["viewer"]

    def assign_user_to_role(self, user_id, role):
        pass


def _bound(processor, auth_core):
    sys.modules["tools"].auth_core = auth_core
    processor.auth_core = auth_core
    fired = []
    module = helpers.bind_like_pylon(
        processor.RPC,
        descriptor=types.SimpleNamespace(config={}),
        context=types.SimpleNamespace(
            event_manager=types.SimpleNamespace(fire_event=lambda *args: fired.append(args)),
        ),
    )
    return module, fired


def _login(module, user_id=None, stable_ref=None, email=EMAIL):
    provider_attr = {"nameid": NAMEID, "attributes": {"email": email, "name": "A User"}}
    if stable_ref is not None:
        provider_attr["stable_ref"] = stable_ref
    return module.init_auth_processor({"user_id": user_id, "provider_attr": provider_attr})


def test_the_pylon_bound_module_exposes_only_the_decorated_handler(processor):
    """Guards the harness itself: undecorated helpers must be absent, as under Pylon."""
    module, _ = _bound(processor, LinkingAuthCore())

    assert hasattr(module, "init_auth_processor")
    assert not hasattr(module, "_ensure_user_provider")
    assert not hasattr(module, "_sync_user_email")


def test_a_successful_login_writes_the_provider_link(processor, pylon_log):
    auth_core = LinkingAuthCore()
    module, _ = _bound(processor, auth_core)

    result = _login(module)

    assert result["user_id"] == auth_core.user_id
    assert auth_core.links[NAMEID] == auth_core.user_id
    assert not [w for w in pylon_log.warnings if "Could not sync identity" in w]


def test_the_stable_reference_is_linked_as_well(processor, pylon_log):
    auth_core = LinkingAuthCore()
    module, _ = _bound(processor, auth_core)

    _login(module, stable_ref=STABLE_REF)

    assert auth_core.links == {STABLE_REF: 7, NAMEID: 7}
    assert not [w for w in pylon_log.warnings if "Could not sync identity" in w]


def test_a_returning_user_gets_the_stable_reference_linked(processor, pylon_log):
    auth_core = LinkingAuthCore()
    auth_core.links[NAMEID] = auth_core.user_id  # linked by a login before the stable ref existed
    module, _ = _bound(processor, auth_core)

    _login(module, user_id=auth_core.user_id, stable_ref=STABLE_REF)

    assert auth_core.links[STABLE_REF] == auth_core.user_id
    assert not [w for w in pylon_log.warnings if "Could not sync identity" in w]


def test_an_idp_email_change_is_followed(processor, pylon_log):
    auth_core = LinkingAuthCore()
    auth_core.links[NAMEID] = auth_core.user_id
    module, _ = _bound(processor, auth_core)

    _login(module, user_id=auth_core.user_id, email="renamed@example.com")

    assert auth_core.emails[auth_core.user_id] == "renamed@example.com"
    assert not [w for w in pylon_log.warnings if "Could not sync identity" in w]
