# Copyright 2021 SAP SE
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from networking_ccloud.common.config import _override_driver_config
from networking_ccloud.common.config import config_driver as config
from networking_ccloud.common import constants as cc_const
from networking_ccloud.tests import base
from networking_ccloud.tests.common import config_fixtures as cfix


class TestDriverConfigValidation(base.TestCase):
    def make_switch(self, name, host="1.2.3.4", platform=cc_const.PLATFORM_EOS):
        return config.Switch(name=name, host=host, platform=platform, user="admin", password="maunz",
                             bgp_source_ip="2.3.4.5")

    def test_switchgroup_two_members(self):
        sw1 = self.make_switch("sw1")
        sw2 = self.make_switch("sw2")
        sw3 = self.make_switch("sw3")
        sg_args = dict(name="foo", availability_zone="qa-de-1a", role="vpod", vtep_ip="1.1.1.1", asn=65001, group_id=1)

        self.assertRaises(ValueError, config.SwitchGroup, members=[sw1], **sg_args)
        self.assertRaises(ValueError, config.SwitchGroup, members=[sw1, sw2, sw3], **sg_args)
        config.SwitchGroup(members=[sw1, sw2], **sg_args)

    def test_switchgroup_group_ids_uniq(self):
        gc = cfix.make_global_config()
        sg1 = cfix.make_switchgroup("seagull", group_id=1000)
        sg2 = cfix.make_switchgroup("tern", group_id=1000)

        self.assertRaisesRegex(ValueError, ".*already in use",
                               config.DriverConfig, global_config=gc, switchgroups=[sg1, sg2], hostgroups=[])

    def test_switchport_lacp_attr_validation(self):
        defargs = {'switch': 'sw-seagull', 'name': 'e1/1/1/1'}

        self.assertRaisesRegex(ValueError, ".*LACP members without LACP being enabled",
                               config.SwitchPort, lacp=False, members=["foo"], **defargs)
        self.assertRaisesRegex(ValueError, ".*is LACP port and has no members",
                               config.SwitchPort, lacp=True, **defargs)
        self.assertRaisesRegex(ValueError, ".*is LACP port and has no members",
                               config.SwitchPort, lacp=True, members=[], **defargs)
        self.assertRaisesRegex(ValueError, ".*has a portchannel id set without LACP being enabled",
                               config.SwitchPort, lacp=False, portchannel_id=23, **defargs)

    def test_switchport_pc_id_parsing(self):
        cases = [("Port-Channel23", 23), ("port-channel42", 42), ("port-Channel 1337", 1337)]
        for pc_name, pc_id in cases:
            sp = config.SwitchPort(switch='sw-seagull', name=pc_name, lacp=True, members=["krakrakra"])
            self.assertEqual(pc_id, sp.portchannel_id, f"Could not parse pc id from {pc_name}")

    def test_switchport_pc_id_is_not_overridden(self):
        sp = config.SwitchPort(switch='sw-seagull', name="Port-Channel23", portchannel_id=42, lacp=True,
                               members=["krakrakra"])
        self.assertEqual(42, sp.portchannel_id)

    def test_hostgroup_direct_binding_mode_default(self):
        hg = config.Hostgroup(metagroup=True, binding_hosts=["foo"], members=["foo"])
        self.assertEqual(False, hg.direct_binding)

        hg = config.Hostgroup(metagroup=True, binding_hosts=["foo"], members=["foo"], direct_binding=True)
        self.assertEqual(True, hg.direct_binding)

        hg = config.Hostgroup(binding_hosts=["foo"], members=[config.SwitchPort(switch="sw-cat", name="e1/1/1")])
        self.assertEqual(True, hg.direct_binding)

        hg = config.Hostgroup(binding_hosts=["foo"], members=[config.SwitchPort(switch="sw-cat", name="e1/1/1")],
                              direct_binding=False)
        self.assertEqual(False, hg.direct_binding)

    def test_cannot_bind_iface_multiple_times(self):
        gc = cfix.make_global_config()
        sg = cfix.make_switchgroup("seagull")
        hg1 = config.Hostgroup(binding_hosts=["foo"], members=[config.SwitchPort(switch="seagull-sw1", name="e1/1/1")])
        hg2 = config.Hostgroup(binding_hosts=["bar"], members=[config.SwitchPort(switch="seagull-sw1", name="e1/1/1")])

        self.assertRaisesRegex(ValueError, ".*Iface seagull-sw1/e1/1/1 is bound two times.*bar.*foo.*",
                               config.DriverConfig, global_config=gc, switchgroups=[sg], hostgroups=[hg1, hg2])

    def test_hostgroup_transit_always_services_own_az(self):
        # should work
        gc = cfix.make_global_config(availability_zones=cfix.make_azs(["qa-de-1a", "qa-de-1b"]))
        sg = cfix.make_switchgroup("seagull", availability_zone="qa-de-1a")
        hg = config.Hostgroup(role="transit", handle_availability_zones=["qa-de-1a"], binding_hosts=["transit1"],
                              members=[config.SwitchPort(switch="seagull-sw1", name="e1/1/1")])
        config.DriverConfig(global_config=gc, switchgroups=[sg], hostgroups=[hg])

        # should break
        hg = config.Hostgroup(role="transit", handle_availability_zones=["qa-de-1b"], binding_hosts=["transit1"],
                              members=[config.SwitchPort(switch="seagull-sw1", name="e1/1/1")])

        self.assertRaisesRegex(ValueError, "Hostgroup transit1 is in AZ qa-de-1a, but.*",
                               config.DriverConfig, global_config=gc, switchgroups=[sg], hostgroups=[hg])

    def test_hostgroup_bgw_require_unnamed_ifaces(self):
        # normal hg with unnamed interface forbidden
        self.assertRaisesRegex(ValueError, ".*Hostgroup ..bgw1.. with role bgw cannot have named switchports.*",
                               config.Hostgroup, binding_hosts=["bgw1"],
                               role="bgw", handle_availability_zones=["qa-de-1a"],
                               members=[config.SwitchPort(switch="seagull-sw1", name="e1/1/1")])

    def test_hostgroup_require_named_ifaces(self):
        # normal hg with unnamed interface forbidden
        self.assertRaisesRegex(ValueError, ".*Hostgroup ..seagull-compute.. needs to have names for each switchport.*",
                               config.Hostgroup, binding_hosts=["seagull-compute"],
                               members=[config.SwitchPort(switch="seagull-sw1")])

    def test_hostgroup_multi_trunk_requires_direct_binding(self):
        # should work
        hg = config.Hostgroup(binding_hosts=["node001-seagull"],
                              members=[config.SwitchPort(switch="seagull-sw1", name="e1/1/1")],
                              allow_multiple_trunk_ports=True)
        self.assertTrue(hg.allow_multiple_trunk_ports)

        # should fail
        self.assertRaisesRegex(ValueError, "can only be set for direct binding hostgroups",
                               config.Hostgroup, binding_hosts=["seagull-compute"],
                               members=["node001-seagull"], metagroup=True,
                               allow_multiple_trunk_ports=True)

    def test_global_default_vlan_ranges(self):
        self.assertRaisesRegex(ValueError, ".*not in format.*", config.GlobalConfig, asn_region=65000,
                               default_vlan_ranges=["foo:bar"], availability_zones=[])
        self.assertRaisesRegex(ValueError, ".*need to be in range.*", config.GlobalConfig, asn_region=65000,
                               default_vlan_ranges=["123:456789"], availability_zones=[])
        self.assertRaisesRegex(ValueError, ".*needs to have a start that.*", config.GlobalConfig, asn_region=65000,
                               default_vlan_ranges=["456:123"], availability_zones=[])

        config.GlobalConfig(asn_region=65000, default_vlan_ranges=["2000:3750"], availability_zones=[], vrfs=[])
        config.GlobalConfig(asn_region=65000, default_vlan_ranges=["2000:2000"], availability_zones=[], vrfs=[])
        config.GlobalConfig(asn_region=65000, default_vlan_ranges=["100:200", "500:600"], availability_zones=[],
                            vrfs=[])

    def test_all_switchgroup_azs_need_to_exist(self):
        global_config = config.GlobalConfig(asn_region=65000, default_vlan_ranges=["2000:3750"],
                                            availability_zones=cfix.make_azs(["qa-de-1a"]), vrfs=[])
        switchgroups = [
            cfix.make_switchgroup("seagull", availability_zone="qa-de-1a"),
            cfix.make_switchgroup("crow", availability_zone="qa-de-1b"),
        ]
        self.assertRaisesRegex(ValueError, ".*SwitchGroup crow has invalid az qa-de-1b.* options are.*qa-de-1a.*",
                               cfix.make_config, switchgroups=switchgroups, hostgroups=[], global_config=global_config)

    def test_l3_infra_network_requires_vrf(self):
        exc = 'If network is given a VRF must be set too'
        self.assertRaisesRegex(ValueError, exc, config.InfraNetwork, name='where-did-the-vrf-go', vlan=1202,
                               networks=['1.2.0.2/24'], vni=1202)

    def test_infra_network_dhcp_requires_network(self):
        exc = 'If dhcp_relays is given a network must be present too'
        self.assertRaisesRegex(ValueError, exc, config.InfraNetwork, name='no-network-lot-cry', vlan=1202,
                               vni=1202, vrf='DHCP-VRF', dhcp_relays=['1.2.3.4'])

    def test_infra_network_dhcp_not_in_network(self):
        exc = 'dhcp_relay .* is contained in network'
        self.assertRaisesRegex(ValueError, exc, config.InfraNetwork, name='why-relay-me', vlan=1202,
                               vni=1202, vrf='DHCP-VRF', dhcp_relays=['1.2.3.4'], networks=['1.2.3.5/24'])

    def test_l3_infra_network_needs_host_bits(self):
        exc = 'Network .* is supposed to be used as gateway and hence needs hosts bits set'
        self.assertRaisesRegex(ValueError, exc, config.InfraNetwork, name='i-am-a-network-address', vlan=1202,
                               vni=1202, vrf='DHCP-VRF', networks=['1.2.3.0/24'])

    def test_l3_infra_network_aggregate_needs_networks(self):
        exc = 'There are more aggregates than networks'
        self.assertRaisesRegex(ValueError, exc, config.InfraNetwork, name='i-miss-my-network', vlan=1202,
                               vni=1202, vrf='ROUTE-ME', aggregates=['1.2.3.0/24'])

    def test_l3_infra_network_with_aggregate(self):
        config.InfraNetwork(name='aggregate-me-if-you-can', vlan=1202, vni=1202, vrf='ROUTE-ME',
                            aggregates=['1.2.3.0/24'], networks=['1.2.3.1/25'])

    def test_l3_infra_network_network_not_contained_in_aggregate(self):
        exc = 'Aggregate .* is not a supernet of any network in networks'
        self.assertRaisesRegex(ValueError, exc, config.InfraNetwork, name='aggregate-me-if-you-can', vlan=1202,
                               vni=1202, vrf='ROUTE-ME', aggregates=['1.2.3.0/24'], networks=['1.2.10.1/24'])

    def test_l3_infra_network_is_aggregate(self):
        exc = 'Aggregate .* is equal to one of the networks'
        self.assertRaisesRegex(ValueError, exc, config.InfraNetwork, name='aggregate-me-if-you-can', vlan=1202,
                               vni=1202, vrf='ROUTE-ME', aggregates=['1.2.3.0/24'], networks=['1.2.3.1/24'])

    def test_infra_network_vrf_presence(self):
        vrfs = cfix.make_vrfs(['ROUTE-ME', 'SWITCH-ME'])
        infra_net_ok = config.InfraNetwork(name='l3-correct-vrf', vlan=1202, vni=1202, vrf='ROUTE-ME')
        infra_net_bad = config.InfraNetwork(name='l3-incorrect-vrf', vlan=1202, vni=1202, vrf='DROP-ME')
        infra_net_l2 = config.InfraNetwork(name='l2', vlan=1202, vni=1202)

        switchgroup = cfix.make_switchgroup('aint-no-cisco-if-it-doesnt-crash')
        global_config = cfix.make_global_config(availability_zones=cfix.make_azs_from_switchgroups([switchgroup]),
                                                vrfs=vrfs)
        hostgroups = cfix.make_hostgroups(switchgroup, infra_networks=[infra_net_ok, infra_net_bad, infra_net_l2])

        self.assertRaisesRegex(ValueError, "Associated VRF DROP-ME of infra network l3-incorrect-vrf is not existing",
                               config.DriverConfig, switchgroups=[switchgroup], hostgroups=hostgroups,
                               global_config=global_config)

    def test_duplicate_vrf_name(self):
        vrfs = cfix.make_vrfs(['ROUTE-ME', 'ROUTE-ME'])

        self.assertRaisesRegex(ValueError, "VRF ROUTE-ME is duplicated",
                               cfix.make_global_config, cfix.make_azs(['monster-az-a']), vrfs=vrfs)

    def test_duplicate_vrf_id(self):
        vrfs = cfix.make_vrfs(['ROUTE-ME', 'SWITCH-ME'])
        vrfs[0].number = vrfs[1].number

        self.assertRaisesRegex(ValueError, "VRF id 2 is duplicated on VRF SWITCH-ME",
                               cfix.make_global_config, cfix.make_azs(['monster-az-a']), vrfs=vrfs)

    def test_get_metagroup_for_child_hostgroup(self):
        # should work
        gc = cfix.make_global_config(availability_zones=cfix.make_azs(["qa-de-1a", "qa-de-1b"]))
        sg1 = cfix.make_switchgroup("seagull", availability_zone="qa-de-1a")
        sg2 = cfix.make_switchgroup("crow", availability_zone="qa-de-1a")
        hg_seagulls = cfix.make_metagroup("seagull")
        hg_crows = cfix.make_hostgroups("crow")
        drv_conf = config.DriverConfig(global_config=gc, switchgroups=[sg1, sg2], hostgroups=hg_seagulls + hg_crows)

        # metagroups have no parent
        parent_hg = drv_conf.get_hostgroup_by_host("nova-compute-seagull")
        self.assertIsNotNone(parent_hg)
        self.assertIsNone(parent_hg.get_parent_metagroup(drv_conf))

        # children are part of their metagroup
        child_hg = drv_conf.get_hostgroup_by_host("node002-seagull")
        self.assertIsNotNone(child_hg)
        self.assertEqual(parent_hg, child_hg.get_parent_metagroup(drv_conf))

        # crow is not part of any metagroup
        crow_hg = drv_conf.get_hostgroup_by_host("node003-crow")
        self.assertIsNotNone(crow_hg)
        self.assertTrue(crow_hg.direct_binding)
        self.assertIsNone(crow_hg.get_parent_metagroup(drv_conf))


class TestDriverConfig(base.TestCase):
    def setUp(self):
        super().setUp()

        switchgroups = [
            cfix.make_switchgroup("seagull", availability_zone="qa-de-1a"),
            cfix.make_switchgroup("transit1", availability_zone="qa-de-1a"),
            cfix.make_switchgroup("bgw1", availability_zone="qa-de-1a"),

            cfix.make_switchgroup("crow", availability_zone="qa-de-1b"),
            cfix.make_switchgroup("transit2", availability_zone="qa-de-1b"),
            cfix.make_switchgroup("bgw2", availability_zone="qa-de-1b"),
        ]
        hg_seagull = cfix.make_metagroup("seagull")
        hg_crow = cfix.make_hostgroups("crow")
        interconnects = [
            cfix.make_interconnect(cc_const.DEVICE_TYPE_TRANSIT, "transit1", "transit1", ["qa-de-1a"]),
            cfix.make_interconnect(cc_const.DEVICE_TYPE_TRANSIT, "transit2", "transit2", ["qa-de-1b"]),
            cfix.make_interconnect(cc_const.DEVICE_TYPE_BGW, "bgw1", "bgw1", ["qa-de-1a"]),
            cfix.make_interconnect(cc_const.DEVICE_TYPE_BGW, "bgw2", "bgw2", ["qa-de-1b"]),
        ]
        hostgroups = hg_seagull + hg_crow + interconnects

        self.drv_conf = cfix.make_config(switchgroups=switchgroups, hostgroups=hostgroups)
        _override_driver_config(self.drv_conf)

    def test_get_hostgroups_by_switches(self):
        switch = self.drv_conf.get_switch_by_name("seagull-sw1")
        hgs = self.drv_conf.get_hostgroups_by_switches([switch.name])
        expected_groups = set(["nova-compute-seagull"] + [f"node{i:03d}-seagull" for i in range(1, 11)])
        self.assertEqual(expected_groups, set(hg.binding_host_name for hg in hgs))

    def test_get_switchgroup_managed_vlans(self):
        infra_net = config.InfraNetwork(name="infra_net_vlan", vlan=42, vni=14, vrf="CC-MGMT", networks=["1.2.3.1/24"])
        sgs = [
            cfix.make_switchgroup("seagull"),
            cfix.make_switchgroup("tern", vlan_ranges=["3333:3333", "1337:1339"]),
        ]
        hgs = cfix.make_metagroup("seagull", meta_kwargs={'infra_networks': [infra_net]})
        gconf = cfix.make_global_config(default_vlan_ranges=["2000:2002"],
                                        availability_zones=cfix.make_azs_from_switchgroups(sgs),
                                        vrfs=cfix.make_vrfs(["CC-MGMT"]))
        drv_conf = cfix.make_config(switchgroups=sgs, hostgroups=hgs, global_config=gconf)

        self.assertEqual({2000, 2001, 2002}, sgs[0].get_managed_vlans(drv_conf, with_infra_nets=False))
        self.assertEqual({42, 2000, 2001, 2002}, sgs[0].get_managed_vlans(drv_conf, with_infra_nets=True))
        self.assertEqual({1337, 1338, 1339, 3333}, sgs[1].get_managed_vlans(drv_conf, with_infra_nets=False))
