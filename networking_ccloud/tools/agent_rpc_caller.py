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

import sys

from neutron.common import config as common_config
from neutron.conf import service as service_conf
from neutron_lib import context
from oslo_config import cfg
from oslo_log import log as logging

from networking_ccloud.common import constants as cc_const
from networking_ccloud.ml2.agent.common.api import CCFabricSwitchAgentRPCClient
from networking_ccloud.ml2.driver_rpc_api import CCFabricDriverRPCClient

LOG = logging.getLogger(__name__)
CONF = cfg.CONF

CLI_OPTS = [
    cfg.BoolOpt("driver", help="Communicate with the driver via RPC"),
    cfg.StrOpt("agent", help="Communicate with an agent via RPC, vendor needs to be specified"),
    cfg.StrOpt("method", default="status", help="Method you want to call on the other side (default status)"),
    cfg.ListOpt("args", default=[], help="Args to pass to method"),
]


def main():
    CONF.register_cli_opts(CLI_OPTS)

    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    service_conf.register_service_opts(service_conf.RPC_EXTRA_OPTS)

    if not (CONF.driver or CONF.agent) or (CONF.driver and CONF.agent):
        print("Please specify either --driver or --agent")
        sys.exit(1)

    if CONF.agent and CONF.agent not in cc_const.SWITCH_AGENT_TOPIC_MAP:
        print(f"Agent type {CONF.agent} is not available, please choose from "
              f"{set(cc_const.SWITCH_AGENT_TOPIC_MAP.keys())}")

    if cfg.CONF.driver:
        client = CCFabricDriverRPCClient()
        topic = client.topic
    else:
        topic = cc_const.SWITCH_AGENT_TOPIC_MAP[CONF.agent]
        client = CCFabricSwitchAgentRPCClient(topic)

    print(f"Doing RPC call {CONF.method}(*{CONF.args}) with topic {topic}")
    ctx = context.get_admin_context()
    print("Result:", getattr(client, CONF.method)(ctx, *CONF.args))


if __name__ == '__main__':
    main()
