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
from networking_ccloud.ml2.agent.nxos.switch import NXOSSwitch
from networking_ccloud.tests import base
from networking_ccloud.tests.common import config_fixtures as cfix


class TestNXOSSwitch(base.TestCase):
    def setUp(self):
        super().setUp()
        drv_conf = cfix.make_config(global_config=cfix.make_global_config(asn_region=65130))
        _override_driver_config(drv_conf)
        cfg_switch = config_driver.Switch(name="seagull-sw1", host="127.0.0.1", platform=cc_const.PLATFORM_NXOS,
                                          user="seagulladm", password="KRAKRAKRA", bgp_source_ip="1.1.1.1")

        cfg.CONF.set_override('prometheus_enabled', False, group='ml2_cc_fabric_agent')
        with mock.patch.object(n_rpc, 'get_client'):
            self.switch = NXOSSwitch(cfg_switch, 65130, 'a', set([100]) | set(range(2000, 3000)),
                                     'cc-nxos-switch-agent')
        self.switch._api = mock.Mock()

    def test_vlans_and_vxmaps_add(self):
        expected_update = [
            ('/System/bd-items/bd-items', {'BD-list': [
                {'fabEncap': 'vlan-1000', 'name': 'nest', 'accEncap': 'vxlan-44444'},
                {'fabEncap': 'vlan-1001', 'name': 'basket', 'accEncap': 'vxlan-55555'}]}),
            ('/System/eps-items/epId-items/Ep-list[epId=1]/nws-items/vni-items', {'Nw-list': [
                {'vni': 44444, 'suppressARP': 'enabled', 'IngRepl-items': {'proto': 'bgp'}},
                {'vni': 55555, 'suppressARP': 'enabled', 'IngRepl-items': {'proto': 'bgp'}}]})]

        cu = agent_msg.SwitchConfigUpdate(switch_name="seagull-sw1", operation=agent_msg.OperationEnum.add)
        cu.add_vlan(1000, "nest")
        cu.add_vlan(1001, "basket")
        cu.add_vxlan_map(44444, 1000)
        cu.add_vxlan_map(55555, 1001)
        self.switch.apply_config_update(cu).result()
        self.switch._api.set.assert_called_with(update=expected_update, delete=[], replace=[])

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
        self.switch._api.set.assert_called_with(update=[], delete=expected_delete, replace=[])

    def test_vlans_and_vxmaps_replace(self):
        def _get(prefix='', path=None, single=True):
            if path[0] == '/System/bd-items/bd-items/BD-list/id' and not single:
                return [555, 2000, 2100]

        self.switch._api.get.side_effect = _get

        expected_delete = ["/System/bd-items/bd-items/BD-list[fabEncap=vlan-2100]"]
        expected_update = [
            ('/System/bd-items/bd-items', {'BD-list': [
                {'fabEncap': 'vlan-2000', 'name': 'nest', 'accEncap': 'vxlan-44444'},
                {'fabEncap': 'vlan-2001', 'name': 'basket', 'accEncap': 'vxlan-55555'}]}),
            ('/System/eps-items/epId-items/Ep-list[epId=1]/nws-items/vni-items', {'Nw-list': [
                {'vni': 44444, 'suppressARP': 'enabled', 'IngRepl-items': {'proto': 'bgp'}},
                {'vni': 55555, 'suppressARP': 'enabled', 'IngRepl-items': {'proto': 'bgp'}}]})]

        cu = agent_msg.SwitchConfigUpdate(switch_name="seagull-sw1", operation=agent_msg.OperationEnum.replace)
        cu.add_vlan(2000, "nest")
        cu.add_vlan(2001, "basket")
        cu.add_vxlan_map(44444, 2000)
        cu.add_vxlan_map(55555, 2001)
        self.switch.apply_config_update(cu).result()
        self.switch._api.set.assert_called_with(update=expected_update, delete=expected_delete, replace=[])

    def test_bgp_add(self):
        # NOTE: nn2 --> nn4, once this fw bug is fixed
        expected_update = [('/System/evpn-items/bdevi-items', {'BDEvi-list': [
            {'encap': 'vxlan-232323', 'rd': 'rd:as2-nn2:4223:232323', 'rttp-items': {'RttP-list': [
                {'type': 'export', 'ent-items': {'RttEntry-list': [{'rtt': 'route-target:as2-nn2:1:232323'}]}},
                {'type': 'import', 'ent-items': {'RttEntry-list': [{'rtt': 'route-target:as2-nn2:1:232323'}]}}]}},
            {'encap': 'vxlan-242424', 'rd': 'rd:as2-nn2:4223:242424', 'rttp-items': {'RttP-list': [
                {'type': 'export', 'ent-items': {'RttEntry-list': [{'rtt': 'route-target:as2-nn2:1:242424'}]}},
                {'type': 'import', 'ent-items': {'RttEntry-list': [{'rtt': 'route-target:as2-nn2:1:242424'}]}}]}}]})]

        cu = agent_msg.SwitchConfigUpdate(switch_name="seagull-sw1", operation=agent_msg.OperationEnum.add)
        cu.add_vxlan_map(232323, 2000)
        cu.add_vxlan_map(242424, 2100)
        cu.bgp = agent_msg.BGP(asn="65000", asn_region="65123", switchgroup_id=4223)
        cu.bgp.add_vlan(2000, 232323, 1)
        cu.bgp.add_vlan(2100, 242424, 1)
        # vlans with no vni mapping are ignored
        cu.bgp.add_vlan(2200, 424242, 1)

        self.switch.apply_config_update(cu).result()
        self.switch._api.set.assert_called_with(update=expected_update, delete=[], replace=[])

    def test_bgp_delete(self):
        expected_delete = [
            '/System/evpn-items/bdevi-items/BDEvi-list[encap=232323]',
            '/System/evpn-items/bdevi-items/BDEvi-list[encap=242424]',
        ]
        cu = agent_msg.SwitchConfigUpdate(switch_name="seagull-sw1", operation=agent_msg.OperationEnum.remove)
        cu.add_vxlan_map(232323, 2000)
        cu.add_vxlan_map(242424, 2100)
        cu.bgp = agent_msg.BGP(asn="65000", asn_region="65123", switchgroup_id=4223)
        cu.bgp.add_vlan(2000, 232323, 1)
        cu.bgp.add_vlan(2100, 242424, 1)
        # vlans with no vni mapping are ignored
        cu.bgp.add_vlan(2200, 424242, 1)

        self.switch.apply_config_update(cu).result()
        self.switch._api.set.assert_called_with(update=[], delete=expected_delete, replace=[])

    def test_bgp_replace(self):
        # FIXME: needs to be implemented once we have VNI cleaning
        # FIXME: think about if we need route target cleaning
        pass

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
        self.switch._api.set.assert_called_with(update=expected_update, delete=[], replace=[])

    def test_ifaces_delete(self):
        expected_update = [
            ('/System/intf-items/phys-items', {'PhysIf-list': [
                {'id': 'eth1/12', 'trunkVlans': '-1000,1001'},
                {'id': 'eth1/15'}]}),
            ('/System/intf-items/aggr-items', {'AggrIf-list': [
                {'id': 'po1337', 'nativeVlan': '', 'trunkVlans': '-2000,2001,2003', 'vlanmapping-items': {}}]}),
        ]
        expected_delete = [
            'System/intf-items/aggr-items/AggrIf-list[id=po1337]/vlanmapping-items/vlantranslatetable-items/'
            'vlan-items/VlanTranslateEntry-list[vlanid=vlan-2000][translatevlanid=vlan-2323]',
            'System/intf-items/aggr-items/AggrIf-list[id=po1337]/vlanmapping-items/vlantranslatetable-items/'
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
        self.switch._api.set.assert_called_with(update=expected_update, delete=expected_delete, replace=[])

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

        self.switch._api.get.side_effect = _get

        expected_delete = [
            'System/intf-items/aggr-items/AggrIf-list[id=po1337]/vlanmapping-items/vlantranslatetable-items/'
            'vlan-items/VlanTranslateEntry-list[vlanid=vlan-123][translatevlanid=vlan-456]',
            'System/intf-items/aggr-items/AggrIf-list[id=po1337]/vlanmapping-items/vlantranslatetable-items/'
            'vlan-items/VlanTranslateEntry-list[vlanid=vlan-2003][translatevlanid=vlan-123]',
        ]
        expected_update = [
            ('/System/intf-items/phys-items', {'PhysIf-list': [
                {'id': 'eth1/12', 'layer': 'Layer2', 'mode': 'trunk',
                 'nativeVlan': '', 'trunkVlans': ['+1000,1001', '-2000,2001']},
                {'id': 'eth1/13', 'layer': 'Layer2', 'mode': 'trunk'},
                {'id': 'eth1/14', 'layer': 'Layer2', 'mode': 'trunk'},
                {'id': 'eth1/15', 'layer': 'Layer2', 'mode': 'trunk', 'descr': 'Hi from the tests!',
                 'nativeVlan': ''}]}),
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
        self.switch._api.set.assert_called_with(update=expected_update, delete=expected_delete, replace=[])

# FIXME: getconfig tests
# FIXME: vni cleaning
