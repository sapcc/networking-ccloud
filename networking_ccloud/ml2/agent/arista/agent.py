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

import os

if not os.environ.get('DISABLE_EVENTLET_PATCHING'):
    import eventlet
    eventlet.monkey_patch()

from oslo_log import log as logging

from networking_ccloud.common import constants as cc_const
from networking_ccloud.ml2.agent.common.agent import CCFabricSwitchAgent

LOG = logging.getLogger(__name__)


class CCFabricAristaSwitchAgent(CCFabricSwitchAgent):
    """Switch Agent implementing Arista functions"""

    @classmethod
    def get_binary_name(cls):
        return 'cc-fabric-arista-agent'

    @classmethod
    def get_agent_topic(cls):
        return cc_const.SWITCH_AGENT_ARISTA_TOPIC

    def status(self, context):
        status = super().status(context=context)
        status['arista'] = "Present"

        return status


def main():
    CCFabricAristaSwitchAgent.run_agent_main()
