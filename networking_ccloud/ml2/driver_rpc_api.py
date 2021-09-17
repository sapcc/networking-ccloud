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

LOG = logging.getLogger(__name__)


class CCFabricDriverAPI:
    def status(self, context):
        return {"driver_state": "running"}


class CCFabricDriverRPCClient:
    """Client side RPC interface definition for talking to the ml2 driver

    API version history:
        1.0 - Initial version

    See neutron/doc/source/contributor/internals/rpc_api.rst for details.
    https://docs.openstack.org/neutron/latest/contributor/internals/rpc_api.html
    """

    def __init__(self, topic=cc_const.CC_DRIVER_TOPIC):
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.topic = topic
        self.client = n_rpc.get_client(target)

    def status(self, context):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'status')
