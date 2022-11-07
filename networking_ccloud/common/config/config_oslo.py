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

from neutron.conf.plugins.ml2.drivers.driver_type import register_ml2_drivers_vlan_opts
from oslo_config import cfg
from oslo_log import log as logging

LOG = logging.getLogger(__name__)

cc_fabric_opts = [
    cfg.StrOpt("driver_config_path",
               help="Path to yaml config file"),
    cfg.BoolOpt("handle_all_l3_gateways", default=True,
                help="Spawn l3 gateways for all external networks. If this is disabled only networks with "
                     "the tag 'gateway-host::cc-fabric' will be considered"),
]

cc_fabric_agent_opts = [
    cfg.IntOpt('persist_config_loop_interval', default=15 * 60,
               help="Interval between config persists (use -1 to disable)"),
    cfg.IntOpt('switch_syncloop_interval', default=15 * 60,
               help="How often to run a full sync of all switches in the fabric (use -1 to disable)"),
]

# make sure we have ml2 vlan opts available before this option is parsed
# as we need to access ml2_type_vlan.network_vlan_ranges in our validation
register_ml2_drivers_vlan_opts()

cfg.CONF.register_opts(cc_fabric_opts, "ml2_cc_fabric")
cfg.CONF.register_opts(cc_fabric_agent_opts, "ml2_cc_fabric_agent")
