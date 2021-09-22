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

VENDOR_ARISTA = "arista"
VENDOR_NXOS = "nxos"
VENDORS = [VENDOR_ARISTA, VENDOR_NXOS]

HANDOVER_VLAN = 'vlan'
HANDOVER_MODES = [HANDOVER_VLAN]

CC_DRIVER_NAME = 'cc-fabric'

# rpc topics
CC_DRIVER_TOPIC = 'cc-fabric-driver'
SWITCH_AGENT_ARISTA_TOPIC = 'cc-fabric-switch-agent-arista'
SWITCH_AGENT_NXOS_TOPIC = 'cc-fabric-switch-agent-nxos'

SWITCH_AGENT_TOPIC_MAP = {
    'arista': SWITCH_AGENT_ARISTA_TOPIC,
    'nxos': SWITCH_AGENT_NXOS_TOPIC,
}
