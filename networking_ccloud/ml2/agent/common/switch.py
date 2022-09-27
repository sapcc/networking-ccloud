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
from functools import wraps

from futurist import ThreadPoolExecutor
from oslo_concurrency import lockutils
from oslo_context import context
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


def run_in_executor(fn):
    """Decorator to run a method in the ThreadPoolExecutor of the class

    The wrapped method thus returns a futurist.Future now instead of its actual
    result.
    """
    @wraps(fn)
    def wrapped(self, *args, **kwargs):
        current_context = context.get_current()

        @wraps(fn)
        def context_preserving_fn(*args, **kwargs):
            if current_context:
                current_context.update_store()
            else:
                # clear the current context of the thread set by the last
                # function so we don't log stuff with the wrong context
                try:
                    delattr(context._request_store, 'context')
                except AttributeError:
                    pass
            return fn(*args, **kwargs)

        return self._executor.submit(context_preserving_fn, self, *args, **kwargs)

    return wrapped


class SwitchBase(abc.ABC):
    def __init__(self, sw_conf, asn_region, managed_vlans, timeout=20, verify_ssl=False):
        self.sw_conf = sw_conf
        self.asn_region = asn_region
        self.managed_vlans = managed_vlans
        self.name = sw_conf.name
        self.host = sw_conf.host
        self.user = sw_conf.user
        self._password = sw_conf.password
        self.timeout = timeout
        self._verify_ssl = verify_ssl
        self._api = None
        self._executor = ThreadPoolExecutor(max_workers=5)

    @classmethod
    @abc.abstractmethod
    def get_platform(cls):
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

    @run_in_executor
    def get_switch_status(self):
        return self._get_switch_status()

    def _get_switch_status(self):
        raise NotImplementedError

    @run_in_executor
    def get_config(self):
        return self._get_config()

    def _get_config(self):
        raise NotImplementedError

    @run_in_executor
    def apply_config_update(self, config):
        with lockutils.lock(name=f"apply-config-update-{self.name}"):
            return self._apply_config_update(config)

    def _apply_config_update(self, config):
        raise NotImplementedError
