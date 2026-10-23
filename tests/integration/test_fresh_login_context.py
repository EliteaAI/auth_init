"""A login only ever names the user its own provider reference maps to (C-1009 hardening).

The provider hands the processor a fresh context. A user id that the provider reference does
not map to (a stale or foreign session) is refused, and the initial global admin role is given
only to the user the admin's own provider reference maps to.
"""
import pytest


def _admin_config(subject):
    subject.descriptor.config["initial_global_admins"] = ["admin"]


def test_a_user_the_provider_reference_does_not_map_to_is_refused(subject, auth_core, auth_ctx):
    auth_core.provider_user_id = 2  # the reference belongs to user 2, the context names user 1

    with pytest.raises(RuntimeError):
        subject.init_auth_processor(auth_ctx)

    assert not auth_core.called("update_user")
    assert not auth_core.called("assign_user_to_role")


def test_a_preset_user_without_any_provider_mapping_is_refused(subject, auth_core, auth_ctx):
    auth_core.provider_user_id = None

    with pytest.raises(RuntimeError):
        subject.init_auth_processor(auth_ctx)


def test_the_mapped_user_logs_in(subject, auth_core, auth_ctx):
    assert subject.init_auth_processor(auth_ctx) is auth_ctx
    assert auth_ctx["user_id"] == 1


def test_initial_admin_role_goes_to_the_user_the_admin_reference_maps_to(subject, auth_core, auth_ctx):
    _admin_config(subject)
    auth_core.get_user_roles = lambda user_id: auth_core._record("get_user_roles", user_id) or []
    auth_ctx["provider_attr"]["nameid"] = "admin"

    subject.init_auth_processor(auth_ctx)

    assert auth_core.called("assign_user_to_role") == [("assign_user_to_role", (1, "super_admin"), {})]


def test_initial_admin_role_is_granted_to_a_newly_created_admin_user(subject, auth_core, auth_ctx):
    _admin_config(subject)
    auth_core.get_user_roles = lambda user_id: auth_core._record("get_user_roles", user_id) or []
    auth_core.errors["get_user"] = LookupError("no such e-mail")  # a first login: created, then mapped
    auth_ctx["user_id"] = None
    auth_ctx["provider_attr"]["nameid"] = "admin"

    subject.init_auth_processor(auth_ctx)

    assert auth_core.called("add_user_provider") == [("add_user_provider", (1, "admin"), {})]
    assert auth_core.called("assign_user_to_role") == [("assign_user_to_role", (1, "super_admin"), {})]


def test_initial_admin_role_never_lands_on_another_user(subject, auth_core, auth_ctx):
    _admin_config(subject)
    auth_core.provider_user_id = 2
    auth_ctx["provider_attr"]["nameid"] = "admin"

    with pytest.raises(RuntimeError):
        subject.init_auth_processor(auth_ctx)

    assert not auth_core.called("assign_user_to_role")
