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
from networking_ccloud.common.config.config_driver import InfraNetwork, AvailabilityZone, VRF
from networking_ccloud.ml2.agent.common import messages as agent_msg
from networking_ccloud.tests import base
from networking_ccloud.tests.common import config_fixtures as cfix


class TestBGPVRF(base.TestCase):

    def test_add_default_rts(self):
        azs = [AvailabilityZone(name=f'az-{x}', suffix=chr(ord('a') - 1 + x), number=x) for x in range(1, 5)]
        vrf1 = agent_msg.BGPVRF(name='VRF1', rd='11')
        asn_region = '9'
        vrf_number = 188
        vrf1.add_default_rts(asn_region, vrf_number, azs[0], azs)
        import_rts = ['9:1188', '9:2188', '9:3188', '9:4188']
        export_rts = ['9:1188']
        self.assertEqual(import_rts, vrf1.rt_imports_evpn)
        self.assertEqual(export_rts, vrf1.rt_exports_evpn)


class TestBGPVRFAggregate(base.TestCase):

    def test_reject_host_bits(self):
        self.assertRaises(ValueError, agent_msg.BGPVRFAggregate, network='10.0.0.1/24', route_map='A')


class TestBGPVRFNetwork(base.TestCase):

    def test_reject_network(self):
        self.assertRaises(ValueError, agent_msg.BGPVRFNetwork, network='10.0.0.0/24', route_map='A')


class TestRouteMap(base.TestCase):

    def test_gen_name(self):
        name = agent_msg.RouteMap.gen_name('VRF1', az_suffix='a', aggregate=False)
        self.assertEqual('RM-VRF1-A', name)
        name = agent_msg.RouteMap.gen_name('VRF1', az_suffix='a', aggregate=True)
        self.assertEqual('RM-VRF1-A-AGGREGATE', name)


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
        bgp.add_vlan(23, 42)
        bgp.add_vlan(23, 42)
        self.assertEqual(1, len(bgp.vlans))
        bgp.add_vlan(13, 37)
        bgp.add_vlan(23, 42)
        bgp.add_vlan(100, 100)
        self.assertEqual(3, len(bgp.vlans))

        bgp.get_or_create_vrf('VRF1', '1')
        bgp.get_or_create_vrf('VRF1', '2')
        bgp.get_or_create_vrf('VRF2', '2')
        self.assertEqual(2, len(bgp.vrfs))

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
            cfix.make_switchgroup("seagull-a", availability_zone="qa-de-1a"),
            cfix.make_switchgroup("seagull-b", availability_zone="qa-de-1b"),
        ]
        seagull_infra_nets = [
            InfraNetwork(name="infra_net_l3", vlan=23, networks=["10.23.42.1/24"], vrf='TEST', vni=6667),
        ]
        hg_seagull_a = cfix.make_metagroup("seagull-a", meta_kwargs={'infra_networks': seagull_infra_nets})
        hg_seagull_b = cfix.make_metagroup("seagull-b", meta_kwargs={'infra_networks': seagull_infra_nets})
        hostgroups = hg_seagull_a + hg_seagull_b
        self.drv_conf = cfix.make_config(switchgroups=switchgroups, hostgroups=hostgroups)
        self.drv_conf.global_config.vrfs.append(VRF(name='SEAEAGLE-123', number=123))
        self.drv_conf.global_config.vrfs.append(VRF(name='NASA-MGMT', number=99))
        _override_driver_config(self.drv_conf)

    def test_add_vrf(self):
        scul = agent_msg.SwitchConfigUpdateList(agent_msg.OperationEnum.add, self.drv_conf)
        hg = self.drv_conf.get_hostgroup_by_host("nova-compute-seagull-a")
        scul.add_vrf(hg, "SEAEAGLE-123")

        swcfg = scul.switch_config_updates["seagull-a-sw1"]

        # check vrf present
        self.assertIn(agent_msg.VRF(name='SEAEAGLE-123', ip_routing=True), swcfg.vrfs)
        # check route-maps present
        Rm = agent_msg.RouteMap
        asn_region = self.drv_conf.global_config.asn_region
        asn = "65100"
        route_maps = [
            Rm(name='RM-SEAEAGLE-123', set_rts=[f'{asn_region}:123']),
            Rm(name='RM-SEAEAGLE-123-AGGREGATE', set_rts=[f'{asn_region}:123', f'{asn_region}:1']),
            Rm(name='RM-SEAEAGLE-123-A', set_rts=[f'{asn_region}:1123']),
            Rm(name='RM-SEAEAGLE-123-A-AGGREGATE', set_rts=[f'{asn_region}:1123', f'{asn_region}:1']),
        ]
        self.assertEqual(route_maps, swcfg.route_maps)
        # check bgp vrf present
        self.assertIsInstance(swcfg.bgp, agent_msg.BGP)
        self.assertEqual(asn_region, swcfg.bgp.asn_region)
        self.assertEqual(asn, swcfg.bgp.asn)
        bgpvrf = [x for x in swcfg.bgp.vrfs if x.name == 'SEAEAGLE-123']
        self.assertEqual(1, len(bgpvrf), 'To few or too many BGPVRFs found')
        bgpvrf = bgpvrf[0]
        self.assertEqual(sorted([f'{asn_region}:1123', f'{asn_region}:2123']), sorted(bgpvrf.rt_imports_evpn))
        self.assertEqual([f'{asn_region}:1123'], bgpvrf.rt_exports_evpn)

    def test_add_l3_networks_in_vrf(self):
        scul = agent_msg.SwitchConfigUpdateList(agent_msg.OperationEnum.add, self.drv_conf)
        hg = self.drv_conf.get_hostgroup_by_host("nova-compute-seagull-a")
        asn_region = self.drv_conf.global_config.asn_region
        asn = "65100"

        scul.add_l3_networks_in_vrf(hg, vrf='NASA-MGMT', network_name='SPACESHUTTLE-OOB',
                                    vni=9090, vlan=2009,
                                    networks=['10.1.1.1/24', '10.2.0.1/16'],
                                    aggregates=['10.2.0.0/16'],
                                    az_local=True)

        swcfg: agent_msg.SwitchConfigUpdate = scul.switch_config_updates["seagull-a-sw1"]
        self.assertEqual(asn_region, swcfg.bgp.asn_region)
        self.assertEqual(asn, swcfg.bgp.asn)
        bgpvrf = [x for x in swcfg.bgp.vrfs if x.name == 'NASA-MGMT']
        self.assertEqual(1, len(bgpvrf), 'To few or too many BGPVRFs found')
        bgpvrf = bgpvrf[0]
        self.assertEqual(f'{asn}:99', bgpvrf.rd)

        expected_aggregates = {agent_msg.BGPVRFAggregate(network='10.2.0.0/16', route_map='RM-NASA-MGMT-A-AGGREGATE')}
        expected_networks = {agent_msg.BGPVRFNetwork(network='10.1.1.1/24', route_map='RM-NASA-MGMT-A'),
                             agent_msg.BGPVRFNetwork(network='10.2.0.1/16', route_map='RM-NASA-MGMT-A-AGGREGATE')}
        self.assertEqual(expected_networks, bgpvrf.networks)
        self.assertEqual(expected_aggregates, bgpvrf.aggregates)

        self.assertIn(agent_msg.VRFVXLANMapping(vrf='NASA-MGMT', vni=9090), swcfg.vrf_vxlan_maps)
        self.assertIn(agent_msg.IfaceConfig(name=f"Vlan2009", description='SPACESHUTTLE-OOB',
                                            vrf='NASA-MGMT', ip_addresses=['10.1.1.1/24', '10.2.0.1/16']),
                      swcfg.ifaces)

        scul.add_l3_networks_in_vrf(hg, vrf='NASA-MGMT', network_name='ISS-OOB',
                                    vni=9890, vlan=2010,
                                    networks=['10.3.1.1/24', '10.4.2.1/24'],
                                    aggregates=['10.4.2.0/24'],
                                    az_local=False)

        expected_networks.add(agent_msg.BGPVRFNetwork(network='10.3.1.1/24', route_map='RM-NASA-MGMT'))
        expected_networks.add(agent_msg.BGPVRFNetwork(network='10.4.2.1/24', route_map='RM-NASA-MGMT-AGGREGATE'))
        expected_aggregates.add(agent_msg.BGPVRFAggregate(network='10.4.2.0/24', route_map='RM-NASA-MGMT-AGGREGATE'))
        self.assertEqual(expected_networks, bgpvrf.networks)
        self.assertEqual(expected_aggregates, bgpvrf.aggregates)

        self.assertIn(agent_msg.VRFVXLANMapping(vrf='NASA-MGMT', vni=9890), swcfg.vrf_vxlan_maps)
        self.assertIn(agent_msg.IfaceConfig(name=f"Vlan2010", description='ISS-OOB',
                                            vrf='NASA-MGMT', ip_addresses=['10.3.1.1/24', '10.4.2.1/24']),
                      swcfg.ifaces)
