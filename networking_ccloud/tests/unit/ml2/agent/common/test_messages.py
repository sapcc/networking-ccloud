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

from networking_ccloud.common.config import config_driver
from networking_ccloud.ml2.agent.common import messages as agent_msg
from networking_ccloud.tests import base
from networking_ccloud.tests.common import config_fixtures as cfix


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
        bgp = agent_msg.BGP(asn=65000, asn_region=65123, switchgroup_id=1000)
        bgp.add_vlan(23, 42, 1)
        bgp.add_vlan(23, 42, 1)
        self.assertEqual(1, len(bgp.vlans))
        bgp.add_vlan(13, 37, 1)
        bgp.add_vlan(23, 42, 1)
        bgp.add_vlan(100, 100, 1)
        self.assertEqual(3, len(bgp.vlans))

    def test_rt_validation(self):
        # int conversion
        self.assertEqual("65130:10091", agent_msg.validate_route_target("842681173419883"))
        self.assertEqual("65000.1337:6667", agent_msg.validate_route_target(144957310991145483))
        self.assertEqual("23.23.23.23:4242", agent_msg.validate_route_target("72645931930423442"))

        # format fixing
        self.assertEqual("65130.23:1234", agent_msg.validate_route_target("4268359703:1234"))
        self.assertEqual("123:123", agent_msg.validate_route_target("123:123"))


class TestSwitchConfigUpdateList(base.TestCase):
    def setUp(self):
        super().setUp()
        switchgroups = [
            cfix.make_switchgroup("seagull", availability_zone="qa-de-1a"),
        ]
        hg_seagull = cfix.make_metagroup("seagull")
        self.drv_conf = cfix.make_config(switchgroups=switchgroups, hostgroups=hg_seagull)

    def test_extra_vlans(self):
        hg_extra = config_driver.Hostgroup(binding_hosts=["seagull-extra"],
                                           members=[cfix.make_switchport("seagull-sw1", "enp0s10")],
                                           extra_vlans=[234, 456])
        scul = agent_msg.SwitchConfigUpdateList(agent_msg.OperationEnum.add, self.drv_conf)
        scul.add_extra_vlans(hg_extra)
        print(scul.switch_config_updates)
        scu = scul.switch_config_updates['seagull-sw1']
        self.assertEqual(1, len(scu.ifaces))
        self.assertEqual({234, 456}, set(scu.ifaces[0].trunk_vlans))
