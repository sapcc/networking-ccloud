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
import requests

from networking_ccloud.common import constants as cc_const
from networking_ccloud.ml2.agent.common.switch import SwitchBase

LOG = logging.getLogger(__name__)


class NXOSSwitch(SwitchBase):
    @classmethod
    def get_platform(self):
        return cc_const.PLATFORM_NXOS

    def login(self):
        self._api = requests.Session()
        self._api.auth = (self.user, self._password)

    @classmethod
    def _to_payload(cls, cmds, format_text):
        if isinstance(cmds, str):
            cmds = [cmds]

        payload = []
        for n, cmd in enumerate(cmds):
            pl = {
                "jsonrpc": "2.0",
                "method": "cli" if not format_text else "cli_ascii",
                "params": {
                    "cmd": cmd,
                    "version": 1,
                },
                "id": n,
            }
            payload.append(pl)
        return payload

    def send_cmd(self, cmd, format_text=False, raw=False, _is_retry=False):
        """Send a command to the switch"""

        headers = {
            'content-type': 'application/json-rpc'
        }
        start_time = time.time()
        try:
            payload = self._to_payload(cmd, format_text=format_text)
            resp = self.api.post(f"https://{self.host}/ins", headers=headers, json=payload, verify=self._verify_ssl)
            # FIXME: do we want to raise for status?
        except Exception:
            LOG.exception("Command failed in %.2fs on %s %s, cmd: %s",
                          time.time() - start_time, self.name, self.host, cmd)
            raise

        LOG.debug("Command succeeded in %.2fs on %s %s, cmd: %s", time.time() - start_time, self.name, self.host, cmd)
        result = resp.json()

        if not raw:
            # unpack the response a bit for easier handling
            if not isinstance(result, list):
                result = [result]

            # FIXME: will there always be a result? No, not if the command failed. should we raise then?
            for n, entry in enumerate(result):
                if 'result' in entry:
                    result[n] = entry['result']['body']

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
            'version': ver['nxos_ver_str'],
            'model': ver['chassis_id'],
            'uptime': ver['rr_ctime'],  # FIXME: convert to seconds since start
        }
