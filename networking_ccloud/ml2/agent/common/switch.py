# Copyright 2021 SAP SE
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import abc

from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class SwitchBase(abc.ABC):
    def __init__(self, sw_conf, timeout=20, verify_ssl=False):
        self.sw_conf = sw_conf
        self.name = sw_conf.name
        self.host = sw_conf.host
        self.user = sw_conf.user
        self._password = sw_conf.password
        self.timeout = timeout
        self._verify_ssl = verify_ssl
        self._api = None

    @classmethod
    @abc.abstractmethod
    def get_vendor(cls):
        pass

    @property
    def api(self):
        if self._api is None:
            self.login()
        return self._api

    @abc.abstractmethod
    def login(self):
        """Login into the switch - should set self._api"""
        pass

    def __str__(self):
        return f"{self.name} ({self.host})"

    def get_switch_status(self):
        raise NotImplementedError

    def apply_config_update(self, config):
        raise NotImplementedError
