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

from neutron_lib import rpc as n_rpc
from oslo_log import log as logging
import oslo_messaging

from networking_ccloud.common import constants as cc_const
from networking_ccloud.ml2.driver_rpc_api import CCFabricDriverRPCClient

LOG = logging.getLogger(__name__)


class CCFabricSwitchAgentAPI:
    """RPC API a Switch Agent needs to implement"""
    target = oslo_messaging.Target(version='1.0')

    def status(self, context):
        return {"agent_responding": True}

    def ping_back_driver(self, context):
        rpc_client = CCFabricDriverRPCClient()
        return {
            'ml2-driver-status': rpc_client.status(context),
        }

    def get_switch_status(self, switches=None):
        raise NotImplementedError

    def apply_config_update(self, context, config):
        raise NotImplementedError


class CCFabricSwitchAgentRPCClient:
    """Client side RPC interface definition for talking to switching agents

    API version history:
        1.0 - Initial version

    See neutron/doc/source/contributor/internals/rpc_api.rst for details.
    https://docs.openstack.org/neutron/latest/contributor/internals/rpc_api.html
    """

    @classmethod
    def get_for_vendor(cls, vendor):
        return cls(cc_const.SWITCH_AGENT_TOPIC_MAP[vendor])

    def __init__(self, topic):
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def status(self, context):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'status')

    def ping_back_driver(self, context):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'ping_back_driver')

    def get_switch_status(self, context, switches=None):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_switch_status', switches=switches)

    def apply_config_update(self, context, config):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'apply_config_update', config=config)
