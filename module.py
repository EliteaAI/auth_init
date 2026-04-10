#!/usr/bin/python3
# coding=utf-8

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

""" Module """

from pylon.core.tools import log  # pylint: disable=E0611,E0401
from pylon.core.tools import module  # pylint: disable=E0611,E0401

from tools import auth_core  # pylint: disable=E0401


class Module(module.ModuleModel):
    """ Pylon module """

    def __init__(self, context, descriptor):
        self.context = context
        self.descriptor = descriptor

    #
    # Module
    #

    def init(self):
        """ Init module """
        log.info("Initializing module")
        # Init
        self.descriptor.init_all(
            url_prefix=auth_core.get_relative_url_prefix(self.descriptor),
        )
        # Register init auth processor
        auth_core.register_auth_processor("auth_init_auth_processor")
        # Ensure root group present
        try:
            auth_core.get_group(1)
        except:  # pylint: disable=W0702
            auth_core.add_group("Root", None, 1)
            for root_permission in self.descriptor.config.get(
                    "initial_root_permissions", []
            ):
                auth_core.add_group_permission(1, 1, root_permission)
        # Ensure system user present
        system_user = "system@centry.user"
        global_admin_role = "admin"
        #
        try:
            system_user_id = auth_core.get_user(email=system_user)["id"]
        except:  # pylint: disable=W0702
            system_user_id = None
        #
        if system_user_id is None:
            system_user_id = auth_core.add_user(system_user, system_user)
            auth_core.add_user_group(system_user_id, 1)
            auth_core.assign_user_to_role(system_user_id, global_admin_role)

    def deinit(self):
        """ De-init module """
        log.info("De-initializing module")
        # Unregister init auth processor
        auth_core.unregister_auth_processor("auth_init_auth_processor")
        # De-init
        self.descriptor.deinit_all()
