# Copyright 2023 SAP SE
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

from unittest import mock

from neutron_lib import rpc as n_rpc
from oslo_config import cfg

from networking_ccloud.common.config import config_driver, _override_driver_config
from networking_ccloud.common import constants as cc_const
from networking_ccloud.ml2.agent.common import messages as agent_msg
from networking_ccloud.ml2.agent.nxos.switch import guess_asn_format, NXOSSwitch
from networking_ccloud.tests import base
from networking_ccloud.tests.common import config_fixtures as cfix


def _gnmi_args_err(**kwargs):
    args = " ".join(f"{k}={v!r}" for k, v in kwargs.items())
    raise Exception(f"[tests] Unmapped GNMI {args}")
    # raise Exception(f"Unmapped GNMI {prefix} {path} single={single} with_path={with_path}")


class TestNXOSSwitch(base.TestCase):
    def setUp(self):
        super().setUp()
        drv_conf = cfix.make_config(global_config=cfix.make_global_config(asn_region=65130))
        _override_driver_config(drv_conf)
        cfg_switch = config_driver.Switch(name="seagull-sw1", host="127.0.0.1", platform=cc_const.PLATFORM_NXOS,
                                          user="seagulladm", password="KRAKRAKRA", bgp_source_ip="1.1.1.1")

        cfg.CONF.set_override('prometheus_enabled', False, group='ml2_cc_fabric_agent')
        with mock.patch.object(n_rpc, 'get_client'):
            self.switch = NXOSSwitch(cfg_switch, asn_region=65130, az_suffix='a',
                                     managed_vlans={100} | set(range(2000, 3000)), managed_vnis=[range(10000, 11000)],
                                     agent_name='cc-nxos-switch-agent')
        self.switch._api = mock.Mock()

    def test_guess_asn_format_works(self):
        self.assertEqual("as2-nn2", guess_asn_format("65000:1"))
        self.assertEqual("as4-nn2", guess_asn_format("424242:1"))

    def test_guess_asn_format_fails(self):
        self.assertRaises(ValueError, guess_asn_format, "invalid")
        self.assertRaises(ValueError, guess_asn_format, "65000.1")

    def test_vlans_and_vxmaps_add(self):
        expected_update = [
            ('/System/bd-items/bd-items', {'BD-list': [
                {'fabEncap': 'vlan-1000', 'name': 'nest', 'accEncap': 'vxlan-44444'},
                {'fabEncap': 'vlan-1001', 'name': 'basket', 'accEncap': 'vxlan-55555'}]}),
            ('/System/eps-items/epId-items/Ep-list[epId=1]/nws-items/vni-items', {'Nw-list': [
                {'vni': 44444, 'suppressARP': 'off', 'IngRepl-items': '',
                 "multisiteIngRepl": "disable"},
                {'vni': 55555, 'suppressARP': 'off', 'IngRepl-items': '',
                 "multisiteIngRepl": "disable"}]})]

        cu = agent_msg.SwitchConfigUpdate(switch_name="seagull-sw1", operation=agent_msg.OperationEnum.add)
        cu.add_vlan(1000, "nest")
        cu.add_vlan(1001, "basket")
        cu.add_vxlan_map(44444, 1000)
        cu.add_vxlan_map(55555, 1001)
        self.switch.apply_config_update(cu).result()
        self.switch._api.set.assert_called_with(delete=[], replace=[], update=expected_update)

    def test_vlans_and_vxmaps_delete(self):
        expected_delete = [
            '/System/bd-items/bd-items/BD-list[fabEncap=vlan-1000]',
            '/System/bd-items/bd-items/BD-list[fabEncap=vlan-1001]',
            '/System/eps-items/epId-items/Ep-list[epId=1]/nws-items/vni-items/Nw-list[vni=44444]',
            '/System/eps-items/epId-items/Ep-list[epId=1]/nws-items/vni-items/Nw-list[vni=55555]']

        cu = agent_msg.SwitchConfigUpdate(switch_name="seagull-sw1", operation=agent_msg.OperationEnum.remove)
        cu.add_vlan(1000, "nest")
        cu.add_vlan(1001, "basket")
        cu.add_vxlan_map(44444, 1000)
        cu.add_vxlan_map(55555, 1001)
        self.switch.apply_config_update(cu).result()
        self.switch._api.set.assert_called_with(delete=expected_delete, replace=[], update=[])

    def test_vlans_and_vxmaps_replace(self):
        def _get(prefix='', path=None, single=True, with_path=False):
            if path[0] == '/System/bd-items/bd-items/BD-list/id' and not single and not with_path:
                return [555, 2000, 2100]
            elif path[0] == '/System/bd-items/bd-items/BD-list/accEncap' and not single and with_path:
                return [
                    ("System/bd-items/bd-items/BD-list[fabEncap=vlan-1]/accEncap", "unknown"),
                    ("System/bd-items/bd-items/BD-list[fabEncap=vlan-2000]/accEncap", "vxlan-44444"),
                    ("System/bd-items/bd-items/BD-list[fabEncap=vlan-4001]/accEncap", "vxlan-10002"),
                ]
            elif path[0] == '/System/eps-items/epId-items/Ep-list[epId=1]/nws-items/vni-items/Nw-list/vni' and \
                    not single and not with_path:
                return [1234, 10001, 44444]
            else:
                _gnmi_args_err(**locals())
                return None

        self.switch._api.get.side_effect = _get

        expected_delete = [
            "/System/bd-items/bd-items/BD-list[fabEncap=vlan-2100]",
            "/System/bd-items/bd-items/BD-list[fabEncap=vlan-4001]/accEncap",
            "/System/eps-items/epId-items/Ep-list[epId=1]/nws-items/vni-items/Nw-list[vni=10001]",
        ]
        expected_update = [
            ('/System/bd-items/bd-items', {'BD-list': [
                {'fabEncap': 'vlan-2000', 'name': 'nest', 'accEncap': 'vxlan-44444'},
                {'fabEncap': 'vlan-2001', 'name': 'basket', 'accEncap': 'vxlan-55555'}]}),
            ('/System/eps-items/epId-items/Ep-list[epId=1]/nws-items/vni-items', {'Nw-list': [
                {'vni': 44444, 'suppressARP': 'off', 'IngRepl-items': '',
                 "multisiteIngRepl": "disable"},
                {'vni': 55555, 'suppressARP': 'off', 'IngRepl-items': '',
                 "multisiteIngRepl": "disable"}]})]

        cu = agent_msg.SwitchConfigUpdate(switch_name="seagull-sw1", operation=agent_msg.OperationEnum.replace)
        cu.add_vlan(2000, "nest")
        cu.add_vlan(2001, "basket")
        cu.add_vxlan_map(44444, 2000)
        cu.add_vxlan_map(55555, 2001)
        self.switch.apply_config_update(cu).result()
        self.switch._api.set.assert_called_with(delete=expected_delete, replace=[], update=expected_update)

    def test_bgp_add(self):
        # NOTE(seba): nn2 --> nn4, once this fw bug is fixed
        expected_replace = [
            ('/System/evpn-items/bdevi-items/BDEvi-list[encap=vxlan-23230]',
             {'encap': 'vxlan-23230', 'rd': 'rd:unknown:0:0', 'rttp-items': {'RttP-list': [
                 {'type': 'export', 'ent-items': {'RttEntry-list': [
                     {'rtt': 'route-target:as2-nn2:1:23230'}]}},
                 {'type': 'import', 'ent-items': {'RttEntry-list': [
                     {'rtt': 'route-target:as2-nn2:1:23230'}]}}]}}),
            ('/System/evpn-items/bdevi-items/BDEvi-list[encap=vxlan-24240]',
             {'encap': 'vxlan-24240', 'rd': 'rd:unknown:0:0', 'rttp-items': {'RttP-list': [
                 {'type': 'export', 'ent-items': {'RttEntry-list': [
                     {'rtt': 'route-target:as2-nn2:1:24240'}]}},
                 {'type': 'import', 'ent-items': {'RttEntry-list': [
                     {'rtt': 'route-target:as2-nn2:1:24240'}]}}]}})
        ]

        cu = agent_msg.SwitchConfigUpdate(switch_name="seagull-sw1", operation=agent_msg.OperationEnum.add)
        cu.add_vxlan_map(23230, 2000)
        cu.add_vxlan_map(24240, 2100)
        cu.bgp = agent_msg.BGP(asn="65000", asn_region="65123", switchgroup_id=4223)
        cu.bgp.add_vlan(2000, 23230, 1)
        cu.bgp.add_vlan(2100, 24240, 1)
        # vlans with no vni mapping are ignored
        cu.bgp.add_vlan(2200, 42420, 1)

        self.switch.apply_config_update(cu).result()
        self.switch._api.set.assert_called_with(delete=[], replace=expected_replace, update=[])

    def test_bgp_delete(self):
        expected_delete = [
            '/System/evpn-items/bdevi-items/BDEvi-list[encap=vxlan-23230]',
            '/System/evpn-items/bdevi-items/BDEvi-list[encap=vxlan-24240]',
        ]
        cu = agent_msg.SwitchConfigUpdate(switch_name="seagull-sw1", operation=agent_msg.OperationEnum.remove)
        cu.add_vxlan_map(23230, 2000)
        cu.add_vxlan_map(24240, 2100)
        cu.bgp = agent_msg.BGP(asn="65000", asn_region="65123", switchgroup_id=4223)
        cu.bgp.add_vlan(2000, 23230, 1)
        cu.bgp.add_vlan(2100, 24240, 1)
        # vlans with no vni mapping are ignored
        cu.bgp.add_vlan(2200, 42420, 1)

        self.switch.apply_config_update(cu).result()
        self.switch._api.set.assert_called_with(delete=expected_delete, replace=[], update=[])

    def test_bgp_replace(self):
        def _get(prefix=None, path=None, unpack=True, single=False):
            if path == ["/System/evpn-items/bdevi-items/BDEvi-list/encap"] and unpack and not single:
                return [
                    "vxlan-1234",
                    "vxlan-10234",
                ]
            else:
                _gnmi_args_err(**locals())
                return None
        self.switch._api.get.side_effect = _get

        expected_replace = [
            ('/System/evpn-items/bdevi-items/BDEvi-list[encap=vxlan-23230]',
             {'encap': 'vxlan-23230', 'rd': 'rd:unknown:0:0', 'rttp-items': {'RttP-list': [
                 {'type': 'export', 'ent-items': {'RttEntry-list': [
                     {'rtt': 'route-target:as2-nn2:1:23230'}]}},
                 {'type': 'import', 'ent-items': {'RttEntry-list': [
                     {'rtt': 'route-target:as2-nn2:1:23230'}]}}]}}),
            ('/System/evpn-items/bdevi-items/BDEvi-list[encap=vxlan-24240]',
             {'encap': 'vxlan-24240', 'rd': 'rd:unknown:0:0', 'rttp-items': {'RttP-list': [
                 {'type': 'export', 'ent-items': {'RttEntry-list': [
                     {'rtt': 'route-target:as2-nn2:1:24240'}]}},
                 {'type': 'import', 'ent-items': {'RttEntry-list': [
                     {'rtt': 'route-target:as2-nn2:1:24240'}]}}]}})
        ]
        expected_delete = [
            '/System/evpn-items/bdevi-items/BDEvi-list[encap=vxlan-10234]'
        ]

        cu = agent_msg.SwitchConfigUpdate(switch_name="seagull-sw1", operation=agent_msg.OperationEnum.replace)
        cu.add_vxlan_map(23230, 2000)
        cu.add_vxlan_map(24240, 2100)
        cu.bgp = agent_msg.BGP(asn="65000", asn_region="65123", switchgroup_id=4223)
        cu.bgp.add_vlan(2000, 23230, 1)
        cu.bgp.add_vlan(2100, 24240, 1)
        # vlans with no vni mapping are ignored
        cu.bgp.add_vlan(2200, 42420, 1)

        self.switch.apply_config_update(cu).result()
        self.switch._api.set.assert_called_with(delete=expected_delete, replace=expected_replace, update=[])

    def test_ifaces_add(self):
        expected_update = [
            ('/System/intf-items/phys-items', {'PhysIf-list': [
                {'id': 'eth1/12', 'layer': 'Layer2', 'mode': 'trunk',
                 'nativeVlan': 'vlan-1000', 'trunkVlans': ['+1000,1001,1003']},
                {'id': 'eth1/13', 'layer': 'Layer2', 'mode': 'trunk'},
                {'id': 'eth1/14', 'layer': 'Layer2', 'mode': 'trunk'},
                {'id': 'eth1/15', 'layer': 'Layer2', 'mode': 'trunk', 'descr': 'Hi from the tests!'}]}),
            ('/System/intf-items/aggr-items', {'AggrIf-list': [
                {'id': 'po1337', 'layer': 'Layer2', 'mode': 'trunk',
                 'nativeVlan': 'vlan-2000', 'trunkVlans': ['+2000,2001,2003'],
                 'vlanmapping-items': {'Enabled': True, 'vlantranslatetable-items': {'vlan-items': {
                     'VlanTranslateEntry-list': [
                         {'vlanid': 'vlan-2000', 'translatevlanid': 'vlan-2323'},
                         {'vlanid': 'vlan-2003', 'translatevlanid': 'vlan-2342'}]}}},
                 'pcId': 1337, 'suspIndividual': 'enable', 'pcMode': 'active',
                 'rsmbrIfs-items': {'RsMbrIfs-list': [
                     {'tDn': "/System/intf-items/phys-items/PhysIf-list[id='eth1/13']"},
                     {'tDn': "/System/intf-items/phys-items/PhysIf-list[id='eth1/14']"}]}}]}),
            ('/System/vpc-items/inst-items/dom-items/if-items', {'If-list': [
                {'id': 1337, 'rsvpcConf-items': {'tDn': "/System/intf-items/aggr-items/AggrIf-list[id='po1337']"}}]}),
        ]

        cu = agent_msg.SwitchConfigUpdate(switch_name="seagull-sw1", operation=agent_msg.OperationEnum.add)
        # create normal interface
        iface1 = agent_msg.IfaceConfig(name='eth1/12', native_vlan=1000)
        iface1.add_trunk_vlan(1000)
        iface1.add_trunk_vlan(1001)
        iface1.add_trunk_vlan(1003)
        cu.add_iface(iface1)

        # create portchannel with members
        iface2 = agent_msg.IfaceConfig(name='po1337', native_vlan=2000, portchannel_id=1337,
                                       members=["eth1/13", "eth1/14"])
        iface2.add_trunk_vlan(2000)
        iface2.add_trunk_vlan(2001)
        iface2.add_trunk_vlan(2003)
        iface2.add_vlan_translation(2000, 2323)
        iface2.add_vlan_translation(2003, 2342)
        cu.add_iface(iface2)

        # create normal interface
        iface3 = agent_msg.IfaceConfig(name='eth1/15', description='Hi from the tests!')
        cu.add_iface(iface3)

        self.switch.apply_config_update(cu).result()
        self.switch._api.set.assert_called_with(delete=[], replace=[], update=expected_update)

    def test_ifaces_delete(self):
        expected_update = [
            ('/System/intf-items/phys-items', {'PhysIf-list': [
                {'id': 'eth1/12', 'trunkVlans': '-1000,1001'},
                {'id': 'eth1/15'}]}),
            ('/System/intf-items/aggr-items', {'AggrIf-list': [
                {'id': 'po1337', 'nativeVlan': '', 'trunkVlans': '-2000,2001,2003', 'vlanmapping-items': {}}]}),
        ]
        expected_delete = [
            '/System/intf-items/aggr-items/AggrIf-list[id=po1337]/vlanmapping-items/vlantranslatetable-items/'
            'vlan-items/VlanTranslateEntry-list[vlanid=vlan-2000][translatevlanid=vlan-2323]',
            '/System/intf-items/aggr-items/AggrIf-list[id=po1337]/vlanmapping-items/vlantranslatetable-items/'
            'vlan-items/VlanTranslateEntry-list[vlanid=vlan-2003][translatevlanid=vlan-2342]',
        ]

        cu = agent_msg.SwitchConfigUpdate(switch_name="seagull-sw1", operation=agent_msg.OperationEnum.remove)
        # create normal interface
        iface1 = agent_msg.IfaceConfig(name='eth1/12')
        iface1.add_trunk_vlan(1000)
        iface1.add_trunk_vlan(1001)
        cu.add_iface(iface1)

        # create portchannel with members
        iface2 = agent_msg.IfaceConfig(name='po1337', native_vlan=2000, portchannel_id=1337,
                                       members=["eth1/13", "eth1/14"])
        iface2.add_trunk_vlan(2000)
        iface2.add_trunk_vlan(2001)
        iface2.add_trunk_vlan(2003)
        iface2.add_vlan_translation(2000, 2323)
        iface2.add_vlan_translation(2003, 2342)
        cu.add_iface(iface2)

        # create normal interface
        iface3 = agent_msg.IfaceConfig(name='eth1/15', description='Hi from the tests!')
        cu.add_iface(iface3)

        self.switch.apply_config_update(cu).result()
        self.switch._api.set.assert_called_with(delete=expected_delete, replace=[], update=expected_update)

    def test_get_bgp_vrf_config(self):
        def _get(prefix='', path=None, single=True, with_path=False):
            if path[0] == '/System/bgp-items/inst-items/dom-items/Dom-list/af-items/DomAf-list/aggaddr-items' and \
                    not single and with_path:
                return [
                    ('System/bgp-items/inst-items/dom-items/Dom-list[name=CC-SEAGULL]/'
                     'af-items/DomAf-list[type=ipv6-ucast]/aggaddr-items',
                     {'AggAddr-list': [{'addr': '2001:db8::/47', 'attrMap': 'RM-CC-SEAGULL-AGGREGATE'}]}),
                    ('System/bgp-items/inst-items/dom-items/Dom-list[name=CC-SEAGULL]/'
                     'af-items/DomAf-list[type=ipv4-ucast]/aggaddr-items',
                     {'AggAddr-list': [
                         {'addr': '1.0.0.0/8', 'attrMap': 'RM-CC-SEAGULL-D-AGGREGATE'},
                         {'addr': '2.0.0.0/8', 'attrMap': 'RM-CC-SEAGULL-AGGREGATE'},
                         {'addr': '3.0.0.0/8', 'attrMap': 'RM-CC-SEAGULL'}]}),
                    ('System/bgp-items/inst-items/dom-items/Dom-list[name=CC-OYSTERCATCHER]/'
                     'af-items/DomAf-list[type=ipv4-ucast]/aggaddr-items',
                     {'AggAddr-list': [{'addr': '4.0.0.0/8', 'attrMap': 'RM-CC-OYSTERCATCHER-AGGREGATE'}]}),
                    ('System/bgp-items/inst-items/dom-items/Dom-list[name=CC-PLOVER-SINGLE-01]/'
                     'af-items/DomAf-list[type=ipv4-ucast]/aggaddr-items',
                     {'AggAddr-list': [{'addr': '5.0.0.0/8', 'attrMap': 'RM-CC-PLOVER-SINGLE-01-AGGREGATE'}]}),
                ]
            elif path[0] == '/System/bgp-items/inst-items/dom-items/Dom-list/af-items/DomAf-list/prefix-items' and \
                    not single and with_path:
                return [
                    ('System/bgp-items/inst-items/dom-items/Dom-list[name=CC-SEAGULL]/'
                     'af-items/DomAf-list[type=ipv6-ucast]/prefix-items',
                     {'AdvPrefix-list': [{'addr': '2a10:db8:1337::/64', 'evpn': 'disabled',
                                          'rtMap': 'RM-CC-SEAGULL'}]}),
                    ('System/bgp-items/inst-items/dom-items/Dom-list[name=CC-SEAGULL]/'
                     'af-items/DomAf-list[type=ipv4-ucast]/prefix-items',
                     {'AdvPrefix-list': [
                         {'addr': '10.0.0.0/24', 'evpn': 'enabled', 'rtMap': 'RM-CC-SEAGULL'},
                         {'addr': '10.0.1.0/24', 'evpn': 'enabled', 'rtMap': 'RM-CC-SEAGULL-D'},
                         {'addr': '10.0.2.0/24', 'evpn': 'enabled', 'rtMap': 'RM-CC-SEAGULL-AGGREGATE'},
                         {'addr': '10.0.3.0/24', 'evpn': 'enabled', 'rtMap': 'RM-CC-SEAGULL-D-AGGREGATE'},
                         {'addr': '11.0.0.0/8', 'evpn': 'enabled', 'rtMap': 'GARBLED-RM'}]}),
                    ('System/bgp-items/inst-items/dom-items/Dom-list[name=CC-OYSTERCATCHER]/'
                     'af-items/DomAf-list[type=ipv4-ucast]/prefix-items',
                     {'AdvPrefix-list': [{'addr': '12.0.0.0/24', 'evpn': 'enabled', 'rtMap': 'RM-CC-OYSTERCATCHER'}]}),
                    ('System/bgp-items/inst-items/dom-items/Dom-list[name=CC-PLOVER-SINGLE-02]/'
                     'af-items/DomAf-list[type=ipv4-ucast]/prefix-items',
                     {'AdvPrefix-list': [{'addr': '13.0.0.0/24', 'evpn': 'enabled',
                                          'rtMap': 'RM-CC-PLOVER-SINGLE-02'}]}),
                ]
            else:
                _gnmi_args_err(**locals())
                return None

        # expected
        #   aggrs: 2001:db8::/47  1.0.0.0/24 2.0.0.0/24 (az) 4.0.0.0/24
        expected_bgp_vrfs = [
            agent_msg.BGPVRF(
                name="CC-OYSTERCATCHER",
                aggregates=[agent_msg.BGPVRFAggregate(network="4.0.0.0/8", az_local=False)],
                networks=[agent_msg.BGPVRFNetwork(network="12.0.0.0/24", az_local=False, ext_announcable=False)],
            ),
            agent_msg.BGPVRF(
                name="CC-PLOVER-SINGLE-01",
                aggregates=[agent_msg.BGPVRFAggregate(network="5.0.0.0/8", az_local=False)],
            ),
            agent_msg.BGPVRF(
                name="CC-PLOVER-SINGLE-02",
                networks=[agent_msg.BGPVRFNetwork(network="13.0.0.0/24", az_local=False, ext_announcable=False)],
            ),
            agent_msg.BGPVRF(
                name="CC-SEAGULL",
                aggregates=[
                    agent_msg.BGPVRFAggregate(network="2001:db8::/47", az_local=False),
                    agent_msg.BGPVRFAggregate(network="1.0.0.0/8", az_local=True),
                    agent_msg.BGPVRFAggregate(network="2.0.0.0/8", az_local=False),
                ],
                networks=[
                    agent_msg.BGPVRFNetwork(network="2a10:db8:1337::/64", az_local=False, ext_announcable=False),
                    agent_msg.BGPVRFNetwork(network="10.0.0.0/24", az_local=False, ext_announcable=False),
                    agent_msg.BGPVRFNetwork(network="10.0.1.0/24", az_local=True, ext_announcable=False),
                    agent_msg.BGPVRFNetwork(network="10.0.2.0/24", az_local=False, ext_announcable=True),
                    agent_msg.BGPVRFNetwork(network="10.0.3.0/24", az_local=True, ext_announcable=True),
                ],
            ),
        ]

        self.switch._api.get.side_effect = _get
        bgp_vrfs = self.switch.get_bgp_vrf_config()
        self.assertEqual(expected_bgp_vrfs, bgp_vrfs)

    def test_bgp_vrf_network_and_aggregate_add(self):
        cu = agent_msg.SwitchConfigUpdate(switch_name="seagull-sw1", operation=agent_msg.OperationEnum.add)
        bgp_vrf = agent_msg.BGPVRF(name="CC-SEAGULL")
        bgp_vrf.add_aggregates([
            agent_msg.BGPVRFAggregate(network="10.180.0.0/16", az_local=False),
            agent_msg.BGPVRFAggregate(network="10.181.0.0/16", az_local=True),
            agent_msg.BGPVRFAggregate(network="2001:db8:4242::/64", az_local=False),
        ])
        bgp_vrf.add_networks([
            agent_msg.BGPVRFNetwork(network="10.180.0.0/24", az_local=False, ext_announcable=False),
            agent_msg.BGPVRFNetwork(network="10.180.1.0/24", az_local=True, ext_announcable=False),
            agent_msg.BGPVRFNetwork(network="10.180.2.0/24", az_local=False, ext_announcable=True),
            agent_msg.BGPVRFNetwork(network="10.180.3.0/24", az_local=True, ext_announcable=True),
            agent_msg.BGPVRFNetwork(network="2001:db8:2323::/64", az_local=False, ext_announcable=False),
        ])
        cu.bgp = agent_msg.BGP(asn="65000", asn_region="65123", switchgroup_id=4223, vrfs=[bgp_vrf])
        svi = agent_msg.VlanIface(vlan=2057, vrf="CC-SEAGULL",
                                  primary_ip_v4="10.180.0.1/24", secondary_ips_v4=["10.180.1.1/24"],
                                  primary_ip_v6="2001:db8::1/64", secondary_ips_v6=["2001:db8:1337::1/64"])
        cu.vlan_ifaces = [svi]

        self.switch.apply_config_update(cu).result()
        self.switch._api.set.assert_called_once()

        expected_replace = [
            ('/System/intf-items/svi-items/If-list[id=vlan2057]',
             {'adminSt': 'up', 'id': 'vlan2057', 'inbMgmt': 'false', 'mtu': 9000,
              'rtvrfMbr-items': {'tDn': "/System/inst-items/Inst-list[name='CC-SEAGULL']"},
              'vlanId': 2057}),
            ('/System/ipv4-items/inst-items/dom-items/Dom-list[name=CC-SEAGULL]/if-items/If-list[id=vlan2057]',
             {'addr-items': {'Addr-list': [{'addr': '10.180.0.1/24', 'type': 'primary'},
                                           {'addr': '10.180.1.1/24', 'type': 'secondary'}]},
              'directedBroadcast': 'disabled', 'forward': 'disabled', 'id': 'vlan2057', 'urpf': 'disabled'}),
            ('/System/icmpv4-items/inst-items/dom-items/Dom-list[name=CC-SEAGULL]/if-items/If-list[id=vlan2057]',
             {'ctrl': 'port-unreachable', 'id': 'vlan2057'}),
            ('/System/ipv6-items/inst-items/dom-items/Dom-list[name=CC-SEAGULL]/if-items/If-list[id=vlan2057]',
             {'addr-items': {'Addr-list': [{'addr': '2001:db8::1/64', 'type': 'primary'},
                                           {'addr': '2001:db8:1337::1/64', 'type': 'secondary'}]},
              'forward': 'disabled', 'id': 'vlan2057', 'urpf': 'disabled'}),
            ('/System/icmpv6-items/inst-items/if-items/If-list[id=vlan2057]',
             {'ctrl': '', 'id': 'vlan2057'}),
            ('/System/hmm-items/fwdinst-items/if-items/FwdIf-list[id=vlan2057]',
             {'adminSt': 'enabled',
              'hybrid-items': {'advertiseGW': False, 'enable': False},
              'id': 'vlan2057', 'mode': 'anycastGW'}),
        ]

        expected_update = [
            ('/System/bgp-items/inst-items/dom-items/Dom-list[name=CC-SEAGULL]/'
             'af-items/DomAf-list[type=ipv4-ucast]/aggaddr-items',
             {'AggAddr-list': [{'addr': '10.180.0.0/16', 'attrMap': 'RM-CC-SEAGULL-AGGREGATE'},
                               {'addr': '10.181.0.0/16', 'attrMap': 'RM-CC-SEAGULL-A-AGGREGATE'}]}),
            ('/System/bgp-items/inst-items/dom-items/Dom-list[name=CC-SEAGULL]/'
             'af-items/DomAf-list[type=ipv4-ucast]/prefix-items',
             {'AdvPrefix-list': [{'addr': '10.180.0.0/24', 'evpn': 'enabled', 'rtMap': 'RM-CC-SEAGULL'},
                                 {'addr': '10.180.1.0/24', 'evpn': 'enabled', 'rtMap': 'RM-CC-SEAGULL-A'},
                                 {'addr': '10.180.2.0/24', 'evpn': 'enabled', 'rtMap': 'RM-CC-SEAGULL-AGGREGATE'},
                                 {'addr': '10.180.3.0/24', 'evpn': 'enabled', 'rtMap': 'RM-CC-SEAGULL-A-AGGREGATE'}]}),
            ('/System/bgp-items/inst-items/dom-items/Dom-list[name=CC-SEAGULL]/'
             'af-items/DomAf-list[type=ipv6-ucast]/aggaddr-items',
             {'AggAddr-list': [{'addr': '2001:db8:4242::/64', 'attrMap': 'RM-CC-SEAGULL-AGGREGATE'}]}),
            ('/System/bgp-items/inst-items/dom-items/Dom-list[name=CC-SEAGULL]/'
             'af-items/DomAf-list[type=ipv6-ucast]/prefix-items',
             {'AdvPrefix-list': [{'addr': '2001:db8:2323::/64', 'rtMap': 'RM-CC-SEAGULL'}]})]

        self.switch._api.set.assert_called_with(delete=[], replace=expected_replace, update=expected_update)

    def test_ifaces_replace(self):
        def _get(prefix='', path=None, unpack=True):
            if path == ["/System/intf-items/*/*/trunkVlans"] and not unpack:
                return {'notification': [{'update': [
                    {'path': 'System/intf-items/aggr-items/AggrIf-list[id=po1337]/trunkVlans', 'val': '2002-2004'},
                    {'path': 'System/intf-items/phys-items/PhysIf-list[id=eth1/12]/trunkVlans',
                     'val': '23,1000,2000-2001'},
                    {'path': 'System/intf-items/phys-items/PhysIf-list[id=eth1/42]/trunkVlans',
                     'val': '1,2,3,4,5,2000-3000'},
                ]}]}
            elif path == ["/System/intf-items/*/*/vlanmapping-items"] and not unpack:
                return {'notification': [{'update': [
                    {'path': 'System/intf-items/aggr-items/AggrIf-list[id=po1337]/vlanmapping-items',
                     'val': {'Enabled': True,
                        'vlantranslatetable-items': {'vlan-items': {'VlanTranslateEntry-list': [
                            {'vlanid': 'vlan-2000', 'translatevlanid': 'vlan-2323'},
                            {'vlanid': 'vlan-2003', 'translatevlanid': 'vlan-123'},
                            {'vlanid': 'vlan-123', 'translatevlanid': 'vlan-456'},
                        ]}}}},
                    {'path': 'System/intf-items/aggr-items/AggrIf-list[id=po1337]/vlanmapping-items',
                     'val': {'Enabled': True}},
                    {'path': 'System/intf-items/aggr-items/AggrIf-list[id=po105]/vlanmapping-items',
                     'val': {'Enabled': False}},
                ]}]}
            else:
                _gnmi_args_err(**locals())
                return None
        self.switch._api.get.side_effect = _get

        expected_delete = [
            '/System/intf-items/aggr-items/AggrIf-list[id=po1337]/vlanmapping-items/vlantranslatetable-items/'
            'vlan-items/VlanTranslateEntry-list[vlanid=vlan-123][translatevlanid=vlan-456]',
            '/System/intf-items/aggr-items/AggrIf-list[id=po1337]/vlanmapping-items/vlantranslatetable-items/'
            'vlan-items/VlanTranslateEntry-list[vlanid=vlan-2003][translatevlanid=vlan-123]',
        ]
        expected_update = [
            ('/System/intf-items/phys-items', {'PhysIf-list': [
                {'id': 'eth1/12', 'layer': 'Layer2', 'mode': 'trunk',
                 'trunkVlans': ['+1000,1001', '-2000,2001']},
                {'id': 'eth1/13', 'layer': 'Layer2', 'mode': 'trunk'},
                {'id': 'eth1/14', 'layer': 'Layer2', 'mode': 'trunk'},
                {'id': 'eth1/15', 'layer': 'Layer2', 'mode': 'trunk', 'descr': 'Hi from the tests!'}]}),
            ('/System/intf-items/aggr-items', {'AggrIf-list': [
                {'id': 'po1337', 'layer': 'Layer2', 'mode': 'trunk',
                 'nativeVlan': 'vlan-2000', 'trunkVlans': ['+2000,2001,2003', '-2002,2004'],
                 'vlanmapping-items': {'Enabled': True, 'vlantranslatetable-items': {'vlan-items': {
                     'VlanTranslateEntry-list': [
                         {'vlanid': 'vlan-2000', 'translatevlanid': 'vlan-2323'},
                         {'vlanid': 'vlan-2003', 'translatevlanid': 'vlan-2342'}]}}},
                 'pcId': 1337, 'suspIndividual': 'enable', 'pcMode': 'active',
                 'rsmbrIfs-items': {'RsMbrIfs-list': [
                     {'tDn': "/System/intf-items/phys-items/PhysIf-list[id='eth1/13']"},
                     {'tDn': "/System/intf-items/phys-items/PhysIf-list[id='eth1/14']"}]}}]}),
            ('/System/vpc-items/inst-items/dom-items/if-items', {'If-list': [
                {'id': 1337, 'rsvpcConf-items': {'tDn': "/System/intf-items/aggr-items/AggrIf-list[id='po1337']"}}]}),
        ]

        cu = agent_msg.SwitchConfigUpdate(switch_name="seagull-sw1", operation=agent_msg.OperationEnum.replace)
        # create normal interface
        iface1 = agent_msg.IfaceConfig(name='eth1/12')
        iface1.add_trunk_vlan(1000)
        iface1.add_trunk_vlan(1001)
        cu.add_iface(iface1)

        # create portchannel with members
        iface2 = agent_msg.IfaceConfig(name='po1337', native_vlan=2000, portchannel_id=1337,
                                       members=["eth1/13", "eth1/14"])
        iface2.add_trunk_vlan(2000)
        iface2.add_trunk_vlan(2001)
        iface2.add_trunk_vlan(2003)
        iface2.add_vlan_translation(2000, 2323)
        iface2.add_vlan_translation(2003, 2342)
        cu.add_iface(iface2)

        # create normal interface
        iface3 = agent_msg.IfaceConfig(name='eth1/15', description='Hi from the tests!')
        cu.add_iface(iface3)

        self.switch.apply_config_update(cu).result()
        self.switch._api.set.assert_called_with(delete=expected_delete, replace=[], update=expected_update)
