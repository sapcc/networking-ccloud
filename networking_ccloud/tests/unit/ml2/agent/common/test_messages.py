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

from networking_ccloud.ml2.agent.common import messages as agent_msg
from networking_ccloud.tests import base


class TestSwitchConfigUpdate(base.TestCase):
    def setUp(self):
        super().setUp()

    def test_value_deduplication(self):
        # Switch config update
        scu = agent_msg.SwitchConfigUpdate(switch_name="seagull-sw1", operation=agent_msg.OperationEnum.add)
        scu.add_vlan(23)
        scu.add_vlan(23)
        self.assertEqual(1, len(scu.vlans))
        scu.add_vlan(42)
        self.assertEqual(2, len(scu.vlans))

        scu.add_vxlan_map(23, 42)
        scu.add_vxlan_map(23, 42)
        self.assertEqual(1, len(scu.vxlan_maps))
        scu.add_vxlan_map(13, 137)
        self.assertEqual(2, len(scu.vxlan_maps))

        # iface
        iface = agent_msg.IfaceConfig(name="e1/1/1/1")
        iface.add_trunk_vlan(23)
        iface.add_trunk_vlan(23)
        self.assertEqual(1, len(iface.trunk_vlans))
        iface.add_trunk_vlan(42)
        self.assertEqual(2, len(iface.trunk_vlans))

        iface.add_vlan_translation(23, 42)
        iface.add_vlan_translation(23, 42)
        self.assertEqual(1, len(iface.vlan_translations))
        iface.add_vlan_translation(13, 37)
        self.assertEqual(2, len(iface.vlan_translations))

        # bgp
        bgp = agent_msg.BGP(asn=65000, asn_region=65123)
        bgp.add_vlan("foo", 23, 42)
        bgp.add_vlan("foo", 23, 42)
        self.assertEqual(1, len(bgp.vlans))
        bgp.add_vlan("foo", 13, 37)
        bgp.add_vlan("bar", 23, 42)
        self.assertEqual(3, len(bgp.vlans))