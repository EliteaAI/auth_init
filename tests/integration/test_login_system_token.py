"""Login must ensure the system token without ever blocking the login (#5262).

access_success_redirect denies the login if any auth processor raises, so the
self-heal is a best-effort call by construction. These tests hold that line: the
call is made on every login, and no failure of it - a missing RPC on an older
auth_core, a suspended user, a database that is down - reaches the caller.
"""
import pytest


def test_the_system_token_is_ensured_on_login(subject, auth_core, auth_ctx):
    subject.init_auth_processor(auth_ctx)

    assert auth_core.called("ensure_system_token") == [
        ("ensure_system_token", (1,), {}),
    ]


def test_it_is_ensured_once(subject, auth_core, auth_ctx):
    """Deduplication is auth_core's job; the processor must not ask twice."""
    subject.init_auth_processor(auth_ctx)

    assert len(auth_core.called("ensure_system_token")) == 1


def test_a_new_user_is_not_provisioned_twice(subject, auth_core, auth_ctx):
    """add_user already creates the token, so this call is the get half."""
    auth_ctx["user_id"] = None
    auth_core.errors["get_user"] = RuntimeError("no such user")

    subject.init_auth_processor(auth_ctx)

    assert len(auth_core.called("add_user")) == 1
    assert len(auth_core.called("ensure_system_token")) == 1


def test_it_is_ensured_for_the_user_the_login_resolved(subject, auth_core, auth_ctx):
    auth_ctx["user_id"] = None
    auth_core.user_id = 42

    subject.init_auth_processor(auth_ctx)

    assert auth_core.called("ensure_system_token")[0][1] == (42,)


# --- the login must survive every failure ---------------------------------


def test_a_failing_rpc_does_not_break_the_login(subject, auth_core, auth_ctx):
    auth_core.errors["ensure_system_token"] = RuntimeError("db is down")

    assert subject.init_auth_processor(auth_ctx) is auth_ctx


def test_a_failing_rpc_is_logged(subject, auth_core, auth_ctx, pylon_log):
    auth_core.errors["ensure_system_token"] = RuntimeError("db is down")

    subject.init_auth_processor(auth_ctx)

    assert pylon_log.warnings == ["Could not ensure system token for user 1"]


def test_a_missing_rpc_does_not_break_the_login(subject, auth_core, auth_ctx):
    """An auth_core older than this series has no ensure_system_token at all."""
    auth_core.errors["ensure_system_token"] = AttributeError(
        "ensure_system_token",
    )

    assert subject.init_auth_processor(auth_ctx) is auth_ctx


def test_a_suspended_user_does_not_break_the_login(subject, auth_core, auth_ctx):
    """ensure_system_token refuses suspended users; that is not the login's call."""
    auth_core.errors["ensure_system_token"] = RuntimeError("User is suspended: 1")

    assert subject.init_auth_processor(auth_ctx) is auth_ctx


def test_the_rest_of_the_login_still_runs_after_a_failure(
        subject, auth_core, auth_ctx, events,
):
    auth_core.errors["ensure_system_token"] = RuntimeError("db is down")

    subject.init_auth_processor(auth_ctx)

    assert [name for name, _ in events.fired] == ["new_ai_user"]
    assert auth_core.called("update_user")


@pytest.mark.parametrize("failure", [
    RuntimeError("db is down"),
    AttributeError("ensure_system_token"),
    ValueError("User is suspended: 1"),
    TimeoutError("rpc timeout"),
])
def test_no_failure_reaches_the_caller(subject, auth_core, auth_ctx, failure):
    auth_core.errors["ensure_system_token"] = failure

    assert subject.init_auth_processor(auth_ctx) is auth_ctx
