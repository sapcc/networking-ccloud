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

from networking_ccloud.common.config import _override_driver_config
from networking_ccloud.common.config.config_driver import InfraNetwork
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
        bgp = agent_msg.BGP(asn=65000, asn_region=65123)
        bgp.add_vlan(23, 42)
        bgp.add_vlan(23, 42)
        self.assertEqual(1, len(bgp.vlans))
        bgp.add_vlan(13, 37)
        bgp.add_vlan(23, 42)
        bgp.add_vlan(100, 100)
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
        seagull_infra_nets = [
            InfraNetwork(name="infra_net_l3", vlan=23, networks=["10.23.42.1/24"], vrf='TEST', vni=6667),
        ]
        hg_seagull = cfix.make_metagroup("seagull", meta_kwargs={'infra_networks': seagull_infra_nets})
        hostgroups = hg_seagull
        self.drv_conf = cfix.make_config(switchgroups=switchgroups, hostgroups=hostgroups)
        _override_driver_config(self.drv_conf)

    def test_add_vrf(self):
        scul = agent_msg.SwitchConfigUpdateList(agent_msg.OperationEnum.add, self.drv_conf)

        hg = self.drv_conf.get_hostgroup_by_host("nova-compute-seagull")
        scul.add_vrf(hg, "TEST", "some network", 31337, 2323,
                     ["10.100.1.0/24"], ["10.100.0.0/23"], az_local=True)

        swcfg = scul.switch_config_updates["seagull-sw1"]
        print(swcfg.dict())

        # check vrf present
        # FIXME: add check
        # check route-maps present
        # FIXME: add check
        # check bgp vrf present
        # FIXME: add check
        # check vrf vxlan maps
        # FIXME: add check
        #   check networks present
        bgpvrf = swcfg.bgp.vrfs[0]
        self.assertEqual(["10.100.0.0/23"], [n.network for n in bgpvrf.aggregates])
        self.assertEqual({"10.100.1.0/24", "10.100.0.0/23"}, {n.network for n in bgpvrf.networks})
