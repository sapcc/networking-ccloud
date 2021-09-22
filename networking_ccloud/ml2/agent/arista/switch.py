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

import time

from oslo_log import log as logging
import pyeapi

from networking_ccloud.common import constants as cc_const
from networking_ccloud.ml2.agent.common.switch import SwitchBase

LOG = logging.getLogger(__name__)


class AristaSwitch(SwitchBase):
    @classmethod
    def get_vendor(self):
        return cc_const.VENDOR_ARISTA

    def login(self):
        self._api = pyeapi.connect(
            transport="https", host=self.host, username=self.user, password=self._password,
            timeout=self.timeout)

    def send_cmd(self, cmd, format='json', raw=False, _is_retry=False):
        """Send a command to the switch"""
        start_time = time.time()
        try:
            result = self.api.execute(cmd, format=format)
        except ConnectionError:
            if not _is_retry:
                return self.send_cmd(cmd, format=format, raw=raw, _is_retry=True)

            LOG.exception("Command failed in %.2fs on %s %s (even after retry), cmd: %s",
                          time.time() - start_time, self.name, self.host, cmd)
            raise
        except Exception:
            LOG.exception("Command failed in %.2fs on %s %s, cmd: %s",
                          time.time() - start_time, self.name, self.host, cmd)
            raise

        LOG.debug("Command succeeded in %.2fs on %s %s, cmd: %s", time.time() - start_time, self.name, self.host, cmd)

        if not raw:
            # unpack the response a bit for easier handling
            # FIXME: will there always be a result? I think so, cause error cases are raised by pyeapi
            result = result['result']
            # unpack the response if user only specified a string as cmd
            if isinstance(cmd, str):
                result = result[0]

        return result

    def get_switch_status(self):
        ver = self.send_cmd("show version")

        return {
            'name': self.name,
            'host': self.host,
            'api_user': self.user,
            'version': ver['version'],
            'model': ver['modelName'],
            'uptime': ver['uptime'],
        }
