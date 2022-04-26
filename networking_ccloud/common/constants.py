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

PLATFORM_EOS = "arista-eos"
PLATFORM_NXOS = "cisco-nx-os"
PLATFORMS = [PLATFORM_EOS, PLATFORM_NXOS]

HANDOVER_VLAN = 'vlan'
HANDOVER_MODES = [HANDOVER_VLAN]

CC_DRIVER_NAME = 'cc-fabric'
VIF_TYPE_CC_FABRIC = 'cc-fabric'

CC_TRANSIT = 'cc-fabric-transit'

DEVICE_TYPE_TRANSIT = 'transit'
DEVICE_TYPE_BGW = 'bgw'
DEVICE_TYPE_BORDER = 'bl'
DEVICE_TYPE_BORDER_AND_TRANSIT = 'bl-transit'

SWITCHGROUP_ROLE_VPOD = 'vpod'
SWITCHGROUP_ROLE_STPOD = 'stpod'
SWITCHGROUP_ROLE_APOD = 'apod'
SWITCHGROUP_ROLE_NETPOD = 'netpod'
SWITCHGROUP_ROLE_BPOD = 'bpod'

AGENT_TYPE_CC_FABRIC = 'CC fabric agent'

# rpc topics
CC_DRIVER_TOPIC = 'cc-fabric-driver'
SWITCH_AGENT_EOS_TOPIC = 'cc-fabric-switch-agent-eos'
SWITCH_AGENT_NXOS_TOPIC = 'cc-fabric-switch-agent-nxos'

SWITCH_AGENT_TOPIC_MAP = {
    PLATFORM_EOS: SWITCH_AGENT_EOS_TOPIC,
    PLATFORM_NXOS: SWITCH_AGENT_NXOS_TOPIC,
}
