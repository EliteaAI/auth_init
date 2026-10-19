"""Linking a sign-in to a user by IdP subject (C-1009, issue #6941).

identity_key decides what a login is matched on:

 * email (default, today's behaviour): by e-mail address. The IdP subject the
   provider supplied is additionally recorded on the matched user when that user
   has none yet.
 * idp_subject: by (issuer, tid, oid). An e-mail match is only a first-time link
   to a user that has no subject yet. A user with a different subject is never
   merged: the login is denied.
"""
import pytest

ISSUER = "https://login.example.com/tenant-1/v2.0"
TID = "tenant-1"
OID = "object-1"
OTHER_OID = "object-2"

EMAIL = "user@example.com"
NAMEID = "user@example.com"


class Directory:
    """An in-memory auth_core: users, their IdP subjects and the calls made."""

    def __init__(self):
        self.users = {}
        self.calls = []
        self.next_id = 100

    def seed(self, user_id, email, subject=(None, None, None)):
        self.users[user_id] = {
            "id": user_id, "email": email,
            "idp_issuer": subject[0], "idp_tid": subject[1], "idp_oid": subject[2],
        }

    def subject_of(self, user_id):
        user = self.users[user_id]
        return (user["idp_issuer"], user["idp_tid"], user["idp_oid"])

    def called(self, name):
        return [call for call in self.calls if call[0] == name]

    # auth_core RPCs
    def get_user(self, user_id=None, email=None):
        self.calls.append(("get_user", user_id, email))
        for user in self.users.values():
            if user["id"] == user_id or (email is not None and user["email"] == email):
                return dict(user)
        raise RuntimeError("No such user found")

    def _by_subject(self, issuer, tid, oid):
        for user in self.users.values():
            if (user["idp_issuer"], user["idp_tid"], user["idp_oid"]) == (issuer, tid, oid):
                return user
        return None

    def get_user_by_idp_subject(self, issuer, tid, oid):
        self.calls.append(("get_user_by_idp_subject", issuer, tid, oid))
        user = self._by_subject(issuer, tid, oid)
        return None if user is None else dict(user)

    def set_user_idp_subject(self, user_id, issuer, tid, oid):
        self.calls.append(("set_user_idp_subject", user_id, issuer, tid, oid))
        if self._by_subject(issuer, tid, oid) not in (None, self.users[user_id]):
            raise RuntimeError("subject belongs to another user")
        if self.subject_of(user_id) not in ((None, None, None), (issuer, tid, oid)):
            raise RuntimeError("user already linked to a different subject")
        self.users[user_id].update(idp_issuer=issuer, idp_tid=tid, idp_oid=oid)
        return True

    def add_user(self, email, name=None):
        self.calls.append(("add_user", email, name))
        self.next_id += 1
        self.seed(self.next_id, email)
        return self.next_id

    def add_user_provider(self, user_id, provider_id):
        self.calls.append(("add_user_provider", user_id, provider_id))

    def add_user_group(self, user_id, group_id):
        self.calls.append(("add_user_group", user_id, group_id))

    def ensure_system_token(self, user_id):
        return "token"

    def update_user(self, id_=None, **kwargs):
        return id_, "Existing Name"

    def get_user_roles(self, user_id):
        return ["viewer"]

    def assign_user_to_role(self, user_id, role):
        pass


@pytest.fixture
def directory():
    return Directory()


@pytest.fixture
def login(processor, directory, events, subject):
    """Run the processor for one OIDC sign-in against the directory."""
    import sys
    sys.modules["tools"].auth_core = directory
    processor.auth_core = directory

    def run(identity_key=None, identity=(ISSUER, TID, OID), user_id=None, with_identity=True):
        if identity_key is not None:
            subject.descriptor.config["identity_key"] = identity_key
        provider_attr = {
            "nameid": NAMEID,
            "attributes": {"email": EMAIL.upper(), "name": "A User"},
        }
        if with_identity:
            provider_attr["identity"] = dict(
                zip(("issuer", "tid", "oid"), identity), sub="sub-1",
            )
        return subject.init_auth_processor(
            {"user_id": user_id, "provider_attr": provider_attr},
        )

    return run


# --- identity_key: email (default) ----------------------------------------


def test_email_mode_is_the_default_and_matches_by_email(login, directory):
    directory.seed(1, EMAIL)

    ctx = login()

    assert ctx["user_id"] == 1
    assert directory.called("get_user_by_idp_subject") == []


def test_email_mode_records_the_subject_on_a_user_that_has_none(login, directory):
    directory.seed(1, EMAIL)

    login(identity_key="email")

    assert directory.subject_of(1) == (ISSUER, TID, OID)


def test_email_mode_records_the_subject_on_a_new_user(login, directory):
    ctx = login()

    assert directory.subject_of(ctx["user_id"]) == (ISSUER, TID, OID)


def test_email_mode_records_the_subject_for_a_provider_known_user(login, directory):
    directory.seed(1, "other@example.com")

    login(user_id=1)

    assert directory.subject_of(1) == (ISSUER, TID, OID)


def test_email_mode_does_not_touch_a_user_that_already_has_a_subject(login, directory, pylon_log):
    directory.seed(1, EMAIL, (ISSUER, TID, OTHER_OID))

    ctx = login()

    assert ctx["user_id"] == 1
    assert directory.subject_of(1) == (ISSUER, TID, OTHER_OID)
    assert directory.called("set_user_idp_subject") == []
    assert any("different IdP subject" in line for line in pylon_log.warnings)


def test_email_mode_skips_recording_without_a_complete_identity(login, directory):
    directory.seed(1, EMAIL)

    login(identity=(ISSUER, TID, None))
    login(with_identity=False)

    assert directory.called("set_user_idp_subject") == []


def test_email_mode_login_survives_a_failed_recording(login, directory, pylon_log):
    directory.seed(1, EMAIL)
    directory.set_user_idp_subject = lambda *a: (_ for _ in ()).throw(RuntimeError("boom"))

    ctx = login()

    assert ctx["user_id"] == 1
    assert any("Could not record IdP subject" in line for line in pylon_log.warnings)


# --- identity_key: idp_subject --------------------------------------------


def test_subject_mode_matches_by_subject_even_when_the_email_changed(login, directory):
    directory.seed(7, "old-address@example.com", (ISSUER, TID, OID))

    ctx = login(identity_key="idp_subject")

    assert ctx["user_id"] == 7
    assert directory.called("add_user") == []
    assert directory.called("set_user_idp_subject") == []


def test_subject_mode_links_a_user_matched_by_email_for_the_first_time(login, directory, pylon_log):
    directory.seed(1, EMAIL)

    ctx = login(identity_key="idp_subject")

    assert ctx["user_id"] == 1
    assert directory.subject_of(1) == (ISSUER, TID, OID)
    assert any(
        "Linked user 1" in line and TID in line and OID in line
        for line in pylon_log.infos
    )
    assert not any(EMAIL in line for line in pylon_log.infos)


def test_subject_mode_links_a_provider_known_user_that_has_no_subject(login, directory):
    directory.seed(1, "other@example.com")

    ctx = login(identity_key="idp_subject", user_id=1)

    assert ctx["user_id"] == 1
    assert directory.subject_of(1) == (ISSUER, TID, OID)


def test_subject_mode_denies_the_same_email_with_a_different_subject(login, directory, pylon_log):
    directory.seed(1, EMAIL, (ISSUER, TID, OTHER_OID))

    with pytest.raises(RuntimeError):
        login(identity_key="idp_subject")

    assert directory.subject_of(1) == (ISSUER, TID, OTHER_OID)
    assert directory.called("add_user") == []
    assert any("different IdP subject" in line for line in pylon_log.errors)


def test_subject_mode_denies_a_provider_known_user_with_a_different_subject(login, directory):
    directory.seed(1, EMAIL, (ISSUER, TID, OTHER_OID))

    with pytest.raises(RuntimeError):
        login(identity_key="idp_subject", user_id=1)


def test_subject_wins_over_a_provider_reference_pointing_elsewhere(login, directory, pylon_log):
    directory.seed(1, "reused-upn@example.com")
    directory.seed(7, "new-person@example.com", (ISSUER, TID, OID))

    ctx = login(identity_key="idp_subject", user_id=1)

    assert ctx["user_id"] == 7
    assert directory.subject_of(1) == (None, None, None)
    assert any("rovider reference" in line for line in pylon_log.warnings)


def test_subject_mode_creates_a_user_when_nothing_matches(login, directory):
    ctx = login(identity_key="idp_subject")

    user_id = ctx["user_id"]
    assert directory.called("add_user")[0][1] == EMAIL
    assert directory.subject_of(user_id) == (ISSUER, TID, OID)
    assert ("add_user_group", user_id, 1) in directory.calls


@pytest.mark.parametrize("identity", [
    (ISSUER, TID, None), (ISSUER, None, OID), (None, TID, OID), ("", TID, OID),
])
def test_subject_mode_denies_an_incomplete_identity(login, directory, identity):
    directory.seed(1, EMAIL)

    with pytest.raises(RuntimeError):
        login(identity_key="idp_subject", identity=identity)

    assert directory.subject_of(1) == (None, None, None)


def test_subject_mode_keeps_email_matching_for_providers_without_identity(login, directory):
    directory.seed(1, EMAIL)

    ctx = login(identity_key="idp_subject", with_identity=False)

    assert ctx["user_id"] == 1
    assert directory.called("set_user_idp_subject") == []


def test_subject_mode_fails_closed_when_linking_fails(login, directory):
    directory.seed(1, EMAIL)
    directory.set_user_idp_subject = lambda *a: (_ for _ in ()).throw(RuntimeError("race"))

    with pytest.raises(RuntimeError):
        login(identity_key="idp_subject")


def test_an_unknown_identity_key_is_refused(login, directory):
    directory.seed(1, EMAIL)

    with pytest.raises(RuntimeError):
        login(identity_key="upn")
