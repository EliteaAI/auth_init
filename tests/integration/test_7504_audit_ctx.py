"""Login-path changes carry a System audit context (#7504).

auth_core records lifecycle events for user creation, first login, IdP name/email
sync and the initial global admin. A login is not an action by an admin, so the
actor is System, labelled with the identity provider, never the user themselves.
"""
import pytest


def ctx_of(auth_core, name):
    return [kwargs.get("audit_ctx") for call, _, kwargs in auth_core.calls if call == name]


def assert_login_ctx(ctx, provider="oidc"):
    assert ctx["actor_type"] == "system"
    assert ctx["actor_id"] is None
    assert ctx["actor_name"] == f"IdP sign-in ({provider})"
    assert ctx["source"] == "provisioning"


def test_new_user_created_with_login_ctx(subject, auth_core, auth_ctx):
    auth_ctx["user_id"] = None
    auth_ctx["provider"] = "oidc"
    auth_core.errors["get_user"] = LookupError("no user")

    subject.init_auth_processor(auth_ctx)

    [ctx] = ctx_of(auth_core, "add_user")
    assert_login_ctx(ctx)


def test_first_login_and_name_sync_carry_login_ctx(subject, auth_core, auth_ctx):
    auth_ctx["provider"] = "saml"

    subject.init_auth_processor(auth_ctx)

    assert_login_ctx(ctx_of(auth_core, "record_first_login")[0], "saml")
    name_ctx = [kwargs["audit_ctx"] for call, _, kwargs in auth_core.calls
                if call == "update_user" and "name" in kwargs]
    assert name_ctx and all(ctx["source"] == "provisioning" for ctx in name_ctx)


def test_email_sync_carries_login_ctx(subject, auth_core, auth_ctx):
    auth_core.email = "old@example.com"
    auth_ctx["provider"] = "oidc"
    original = auth_core.get_user

    def get_user(email=None, **kwargs):
        if email is not None:
            raise LookupError(email)
        return original(email=email, **kwargs)

    auth_core.get_user = get_user

    subject.init_auth_processor(auth_ctx)

    email_ctx = [kwargs["audit_ctx"] for call, _, kwargs in auth_core.calls
                 if call == "update_user" and "email" in kwargs]
    assert len(email_ctx) == 1
    assert_login_ctx(email_ctx[0])


def test_initial_global_admin_carries_login_ctx(subject, auth_core, auth_ctx):
    subject.descriptor.config["initial_global_admins"] = ["user@example.com"]
    auth_core.get_user_roles = lambda user_id: set()
    auth_ctx["provider"] = "form"

    subject.init_auth_processor(auth_ctx)

    assert auth_core.called("assign_user_to_role")
    assert_login_ctx(auth_core.audit_ctx_of_assign, "form")


def test_unknown_provider_still_labelled(subject, auth_core, auth_ctx):
    auth_ctx.pop("provider", None)

    subject.init_auth_processor(auth_ctx)

    assert ctx_of(auth_core, "record_first_login")[0]["actor_name"] == "IdP sign-in (unknown)"
