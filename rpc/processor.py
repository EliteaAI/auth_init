#!/usr/bin/python3
# coding=utf-8
# pylint: disable=C0115,C0116

#   Copyright 2026 EPAM Systems
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

""" RPC """

from datetime import datetime

from pylon.core.tools import web, log  # pylint: disable=E0401,E0611,W0611

from plugins.auth_core.tools import rpc_tools  # pylint: disable=E0401

from tools import auth_core  # pylint: disable=E0401


IDENTITY_KEYS = ("email", "idp_subject")

SUBJECT_FIELDS = ("idp_issuer", "idp_tid", "idp_oid")


def _identity_subject(auth_ctx):
    """ (issuer, tid, oid) the provider vouched for; None if it supplied no identity

    A tuple with a None/empty part means the provider supplies an identity but not
    a complete one (for example a personal account without tid/oid).
    """
    identity = auth_ctx["provider_attr"].get("identity")
    if not isinstance(identity, dict):
        return None
    #
    parts = tuple(identity.get(key) or None for key in ("issuer", "tid", "oid"))
    return tuple(part if isinstance(part, str) else None for part in parts)


def _user_subject(user):
    """ (issuer, tid, oid) stored on a user row; (None, None, None) for none """
    return tuple((user.get(field) or None) for field in SUBJECT_FIELDS)


def _record_idp_subject(user_id, subject):
    """ email mode: add the provider's subject to a user that has none (best effort)

    The login is matched by e-mail in this mode, so recording the subject must not
    be able to fail it: a missing RPC on an older auth_core, a subject another user
    already carries - all are logged and skipped.
    """
    try:
        current = _user_subject(auth_core.get_user(user_id=user_id))
        if current == (None, None, None):
            auth_core.set_user_idp_subject(user_id, *subject)
            log.info("Recorded IdP subject on user %s: tid=%s oid=%s", user_id, subject[1], subject[2])
        elif current != subject:
            log.warning(
                "User %s matched by e-mail carries a different IdP subject "
                "(tid=%s oid=%s) than this login (tid=%s oid=%s)",
                user_id, current[1], current[2], subject[1], subject[2],
            )
    except:  # pylint: disable=W0702
        log.warning("Could not record IdP subject for user %s", user_id, exc_info=True)


def _belongs_to_provider(user_id, user_provider_id) -> bool:
    """True when ``user_provider_id`` is a provider reference of ``user_id``."""
    try:
        return auth_core.get_user_from_provider(user_provider_id)["id"] == user_id
    except Exception:  # pylint: disable=W0703  # no mapping for this reference
        return False


def _resolve_by_idp_subject(auth_ctx, subject, user_email, user_name, user_provider_id):
    """ idp_subject mode: set auth_ctx["user_id"] by (issuer, tid, oid), or raise

    The subject is the key. An e-mail (or provider reference) match is only a
    first-time link to a user that carries no subject yet; a user with another
    subject is never merged.
    """
    if None in subject:
        log.error("Login denied: identity_key is idp_subject but the provider did not supply issuer, tid and oid")
        raise RuntimeError("Login denied: no complete IdP subject")
    #
    issuer, tid, oid = subject
    #
    found = auth_core.get_user_by_idp_subject(issuer, tid, oid)
    if found is not None:
        if auth_ctx["user_id"] not in (None, found["id"]):
            log.warning(
                "Provider reference points to user %s but IdP subject (tid=%s oid=%s) "
                "belongs to user %s: using the IdP subject",
                auth_ctx["user_id"], tid, oid, found["id"],
            )
        auth_ctx["user_id"] = found["id"]
        return
    #
    candidate = None
    if auth_ctx["user_id"] is not None:
        candidate = auth_core.get_user(user_id=auth_ctx["user_id"])
    else:
        try:
            candidate = auth_core.get_user(email=user_email)
        except:  # pylint: disable=W0702
            log.info("No users with same email, creating new one")
    #
    if candidate is not None:
        if _user_subject(candidate) != (None, None, None):
            log.error(
                "Login denied: user %s has a different IdP subject than this login "
                "(tid=%s oid=%s); not merging", candidate["id"], tid, oid,
            )
            raise RuntimeError("Login denied: user is linked to a different IdP subject")
        user_id = candidate["id"]
        auth_core.set_user_idp_subject(user_id, issuer, tid, oid)
        log.info("Linked user %s to IdP subject: tid=%s oid=%s", user_id, tid, oid)
        if auth_ctx["user_id"] is None:
            auth_core.add_user_provider(user_id, user_provider_id)
    else:
        user_id = auth_core.add_user(user_email, user_name)
        auth_core.add_user_provider(user_id, user_provider_id)
        auth_core.add_user_group(user_id, 1)
        auth_core.set_user_idp_subject(user_id, issuer, tid, oid)
        log.info("Created user: %s", user_id)
    #
    auth_ctx["user_id"] = user_id


class RPC:  # pylint: disable=R0903,E1101

    @web.rpc("auth_init_auth_processor")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def init_auth_processor(self, auth_ctx):
        user_provider_id = auth_ctx["provider_attr"]["nameid"]
        # A login may only name the user its own provider reference maps to. The provider
        # hands over a fresh context, so a pre-set user id that this reference does not map
        # to is a stale or foreign session: deny instead of attaching the identity to it.
        if auth_ctx.get("user_id") is not None and not _belongs_to_provider(auth_ctx["user_id"], user_provider_id):
            log.error("Login denied: session user %s is not the user of provider identity %r",
                      auth_ctx["user_id"], user_provider_id)
            raise RuntimeError("Login denied: identity mismatch")
        # Ensure user is present
        attributes = auth_ctx["provider_attr"].get("attributes", {})
        #
        remap_attributes = self.descriptor.config.get("remap_attributes", {})
        if isinstance(remap_attributes, dict):
            for key, value in remap_attributes.items():
                if key not in attributes and value in attributes:
                    log.info("Remapping attribute %s to %s", value, key)
                    attributes[key] = attributes[value]
        #
        user_email = attributes.get("email") or f"{user_provider_id}@centry.user"
        user_email = user_email.lower()
        #
        if attributes.get("given_name") and attributes.get("family_name"):
            user_name = f"{attributes.get('given_name')} {attributes.get('family_name')}"
        elif attributes.get("name"):
            user_name = attributes.get("name")
        else:
            user_name = user_email
        #
        identity_key = self.descriptor.config.get("identity_key", "email")
        if identity_key not in IDENTITY_KEYS:
            log.error("Unknown identity_key %r, expected one of %s", identity_key, IDENTITY_KEYS)
            raise RuntimeError("Login denied: invalid identity_key")
        #
        subject = _identity_subject(auth_ctx)
        #
        if identity_key == "idp_subject" and subject is not None:
            _resolve_by_idp_subject(auth_ctx, subject, user_email, user_name, user_provider_id)
        elif auth_ctx["user_id"] is None:
            user_id = None
            #
            try:
                user_id = auth_core.get_user(email=user_email)["id"]
                #
                auth_core.add_user_provider(user_id, user_provider_id)
                #
                auth_ctx["user_id"] = user_id
            except:  # pylint: disable=W0702
                log.exception("No users with same email, creating new one")
            #
            if user_id is None:
                user_id = auth_core.add_user(user_email, user_name)
                #
                auth_core.add_user_provider(user_id, user_provider_id)
                auth_core.add_user_group(user_id, 1)
                #
                auth_ctx["user_id"] = user_id
                log.info("Created user: %s", user_id)
        #
        user_id = auth_ctx["user_id"]
        #
        if identity_key == "email" and subject is not None and None not in subject:
            _record_idp_subject(user_id, subject)
        #
        # Heal a user whose system token was removed outside the platform.
        # access_success_redirect denies the login if any processor raises, so
        # this must never be able to lock a user out.
        try:
            auth_core.ensure_system_token(user_id)
        except:  # pylint: disable=W0702
            log.warning(
                "Could not ensure system token for user %s", user_id, exc_info=True,
            )
        #
        self.context.event_manager.fire_event("new_ai_user", {
            "user_id": user_id,
            "user_email": user_email,
        })
        #
        # Ensure global_admin is set
        #
        _, returning_name = auth_core.update_user(id_=user_id, last_login=datetime.now())
        if not returning_name:
            auth_core.update_user(id_=user_id, name=user_name)
        #
        global_admin_role = "super_admin"
        initial_global_admins = self.descriptor.config.get("initial_global_admins", [])
        #
        # Only the user this provider reference maps to may receive the initial admin role
        if user_provider_id in initial_global_admins and _belongs_to_provider(user_id, user_provider_id):
            global_user_roles = auth_core.get_user_roles(user_id)
            log.info("User roles: %s", global_user_roles)
            #
            if not global_user_roles:
                auth_core.assign_user_to_role(user_id, global_admin_role)
                log.info("Added role for %s: %s", user_id, global_admin_role)
        #
        return auth_ctx
