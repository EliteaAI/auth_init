"""Login records the first login best-effort, before last_login is set (#7490).

auth_core only records a user whose last_login is still empty, so the call has
to come first and carry the same timestamp. Like ensure_system_token it must
never be able to deny the login.
"""
import pytest


def test_the_first_login_is_recorded_on_login(subject, auth_core, auth_ctx):
    subject.init_auth_processor(auth_ctx)

    calls = auth_core.called("record_first_login")
    assert len(calls) == 1
    assert calls[0][1][0] == 1


def test_it_uses_the_last_login_timestamp(subject, auth_core, auth_ctx):
    subject.init_auth_processor(auth_ctx)

    (_, (_, when), _), = auth_core.called("record_first_login")
    last_login = next(
        kwargs["last_login"] for _, _, kwargs in auth_core.called("update_user")
        if "last_login" in kwargs
    )
    assert when == last_login


def test_it_runs_before_last_login_is_set(subject, auth_core, auth_ctx):
    subject.init_auth_processor(auth_ctx)

    names = [name for name, _, kwargs in auth_core.calls
             if name == "record_first_login" or "last_login" in kwargs]
    assert names == ["record_first_login", "update_user"]


def test_it_is_recorded_for_the_user_the_login_resolved(subject, auth_core, auth_ctx):
    auth_ctx["user_id"] = None
    auth_core.user_id = 42

    subject.init_auth_processor(auth_ctx)

    assert auth_core.called("record_first_login")[0][1][0] == 42


@pytest.mark.parametrize("failure", [
    RuntimeError("db is down"),
    AttributeError("record_first_login"),
    TimeoutError("rpc timeout"),
])
def test_no_failure_breaks_the_login(subject, auth_core, auth_ctx, failure):
    auth_core.errors["record_first_login"] = failure

    assert subject.init_auth_processor(auth_ctx) is auth_ctx
    assert any("last_login" in kwargs for _, _, kwargs in auth_core.called("update_user"))


def test_a_failure_is_logged(subject, auth_core, auth_ctx, pylon_log):
    auth_core.errors["record_first_login"] = RuntimeError("db is down")

    subject.init_auth_processor(auth_ctx)

    assert "Could not record first login for user 1" in pylon_log.warnings
