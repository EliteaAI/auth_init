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


class RPC:  # pylint: disable=R0903,E1101

    @web.rpc("auth_init_auth_processor")
    @rpc_tools.wrap_exceptions(RuntimeError)
    def init_auth_processor(self, auth_ctx):
        user_provider_id = auth_ctx["provider_attr"]["nameid"]
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
        if auth_ctx["user_id"] is None:
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
        if user_provider_id in initial_global_admins:
            global_user_roles = auth_core.get_user_roles(user_id)
            log.info("User roles: %s", global_user_roles)
            #
            if not global_user_roles:
                auth_core.assign_user_to_role(user_id, global_admin_role)
                log.info("Added role for %s: %s", user_id, global_admin_role)
        #
        return auth_ctx
