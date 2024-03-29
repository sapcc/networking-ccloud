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

from oslo_log import log as logging

from networking_ccloud.common import constants as cc_const
from networking_ccloud.ml2.agent.common.agent import CCFabricSwitchAgent
from networking_ccloud.ml2.agent.eos.switch import EOSSwitch

LOG = logging.getLogger(__name__)


class CCFabricEOSSwitchAgent(CCFabricSwitchAgent):
    """Switch Agent implementing Arista EOS functions"""

    @classmethod
    def get_binary_name(cls):
        return 'cc-eos-switch-agent'

    @classmethod
    def get_agent_topic(cls):
        return cc_const.SWITCH_AGENT_EOS_TOPIC

    @classmethod
    def get_switch_class(cls):
        return EOSSwitch

    def status(self, context):
        status = super().status(context=context)
        status['eos'] = "Present"

        return status


def main():
    CCFabricEOSSwitchAgent.run_agent_main()
