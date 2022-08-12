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

from unittest import mock

from networking_ccloud.common.config import config_driver, _override_driver_config
from networking_ccloud.common import constants as cc_const
from networking_ccloud.ml2.agent.common import messages
from networking_ccloud.ml2.agent.eos.switch import EOSSwitch
from networking_ccloud.tests import base
from networking_ccloud.tests.common import config_fixtures as cfix


class TestEOSConfigUpdates(base.TestCase):
    def setUp(self):
        super().setUp()
        drv_conf = cfix.make_config(global_config=cfix.make_global_config(asn_region=65130))
        _override_driver_config(drv_conf)
        cfg_switch = config_driver.Switch(name="seagull-sw1", host="127.0.0.1", platform=cc_const.PLATFORM_EOS,
                                          user="seagulladm", password="KRAKRAKRA", bgp_source_ip="1.1.1.1")
        self.switch = EOSSwitch(cfg_switch)
        self.switch._api = mock.Mock()

    def test_add_vlans(self):
        expected_update = [
            ('network-instances/network-instance[name=default]/vlans',
             {'vlan': [
                 {'vlan-id': 1000, 'config': {'name': 'nest', 'vlan-id': 1000}},
                 {'vlan-id': 1001, 'config': {'name': 'basket', 'vlan-id': 1001}}]})]

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.add)
        cu.add_vlan(1000, "nest")
        cu.add_vlan(1001, "basket")
        self.switch.apply_config_update(cu)
        self.switch._api.set.assert_called_with(update=expected_update, delete=[], replace=[])

    def test_add_everything(self):
        def _get(prefix):
            if prefix == 'interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis':
                return {'arista-exp-eos-vxlan:vlan-to-vni': [{'vlan': 1337, 'vni': 232323}]}
            elif prefix == 'interfaces':
                return {
                    'openconfig-interfaces:interface': []}
        self.switch._api.get.side_effect = _get

        expected_update_config = [
            ('network-instances/network-instance[name=default]/vlans',
             {'vlan': [{'config': {'name': 'nest', 'vlan-id': 1000}, 'vlan-id': 1000},
                       {'config': {'name': 'basket', 'vlan-id': 1001}, 'vlan-id': 1001}]}),
            ('interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis',
             {'vlan-to-vni': [{'vlan': 1000, 'vni': 232323}]}),
            ('interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis',
             {'vlan-to-vni': [{'vlan': 1001, 'vni': 424242}]}),
            ('arista/eos/arista-exp-eos-evpn:evpn/evpn-instances',
             {'evpn-instance': [{'config': {'name': '1000',
                                            'route-distinguisher': '4223:232323',
                                            'redistribute': ['LEARNED']},
                                 'name': '1000',
                                 'route-target': {'config': {'export': ['65123:232323'],
                                                             'import': ['65123:232323']}},
                                 'vlans': {'vlan': [{'config': {'vlan-id': 1000},
                                                     'vlan-id': 1000}]}}]}),
            ('interfaces/interface[name=Port-Channel23]/aggregation',
             {'config': {'arista-intf-augments:fallback': 'individual',
                         'arista-intf-augments:mlag': 23,
                         'lag-type': 'LACP'},
              'switched-vlan': {'config': {'interface-mode': 'TRUNK',
                                           'native-vlan': 1000,
                                           'trunk-vlans': ['1000..1001'],
                                           'vlan-translation': {'egress': [{'config': {'bridging-vlan': 2323,
                                                                                       'translation-key': 1000},
                                                                            'translation-key': 1000},
                                                                           {'config': {'bridging-vlan': 1337,
                                                                                       'translation-key': 1001},
                                                                            'translation-key': 1001}],
                                                                'ingress': [{'config': {'bridging-vlan': 1000,
                                                                                        'translation-key': 2323},
                                                                             'translation-key': 2323},
                                                                            {'config': {'bridging-vlan': 1001,
                                                                                        'translation-key': 1337},
                                                                             'translation-key': 1337}]}}}}),
            ('interfaces/interface[name=Ethernet4/1]/ethernet',
             {'config': {'aggregate-id': 'Port-Channel23'},
              'switched-vlan': {'config': {'interface-mode': 'TRUNK',
                                           'native-vlan': 1000,
                                           'trunk-vlans': ['1000..1001'],
                                           'vlan-translation': {'egress': [{'config': {'bridging-vlan': 2323,
                                                                                       'translation-key': 1000},
                                                                            'translation-key': 1000},
                                                                           {'config': {'bridging-vlan': 1337,
                                                                                       'translation-key': 1001},
                                                                            'translation-key': 1001}],
                                                                'ingress': [{'config': {'bridging-vlan': 1000,
                                                                                        'translation-key': 2323},
                                                                             'translation-key': 2323},
                                                                            {'config': {'bridging-vlan': 1001,
                                                                                        'translation-key': 1337},
                                                                             'translation-key': 1337}]}}}}),
            ('interfaces/interface[name=Ethernet4/2]/ethernet',
             {'config': {'aggregate-id': 'Port-Channel23'},
              'switched-vlan': {'config': {'interface-mode': 'TRUNK',
                                           'native-vlan': 1000,
                                           'trunk-vlans': ['1000..1001'],
                                           'vlan-translation': {'egress': [{'config': {'bridging-vlan': 2323,
                                                                                       'translation-key': 1000},
                                                                            'translation-key': 1000},
                                                                           {'config': {'bridging-vlan': 1337,
                                                                                       'translation-key': 1001},
                                                                            'translation-key': 1001}],
                                                                'ingress': [{'config': {'bridging-vlan': 1000,
                                                                                        'translation-key': 2323},
                                                                             'translation-key': 2323},
                                                                            {'config': {'bridging-vlan': 1001,
                                                                                        'translation-key': 1337},
                                                                             'translation-key': 1337}]}}}}),
            ('interfaces/interface[name=Ethernet23/1]/ethernet',
             {'switched-vlan': {'config': {'interface-mode': 'TRUNK',
                                           'trunk-vlans': ['1001']}}})]
        expected_delete_config = [
            "interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis/"
            "vlan-to-vni[vlan=1337]"
        ]

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.add)
        # vlans
        cu.add_vlan(1000, "nest")
        cu.add_vlan(1001, "basket")

        # vxlan maps
        cu.add_vxlan_map(232323, 1000)
        cu.add_vxlan_map(424242, 1001)

        cu.add_vrf_vxlan_map("VRF-LAUGHING-GULL", 232323)
        cu.add_vrf_vxlan_map("VRF-CASPIAN-TERN", 31337)

        # bgp stuff / vlans
        cu.bgp = messages.BGP(asn="65000", asn_region="65123", switchgroup_id=4223)
        cu.bgp.add_vlan(1000, 232323)

        # interfaces
        iface1 = messages.IfaceConfig(name="Port-Channel23", portchannel_id=23, native_vlan=1000,
                                      members=["Ethernet4/1", "Ethernet4/2"])
        iface1.add_trunk_vlan(1000)
        iface1.add_trunk_vlan(1001)
        iface1.add_vlan_translation(1000, 2323)
        iface1.add_vlan_translation(1001, 1337)
        cu.add_iface(iface1)

        iface2 = messages.IfaceConfig(name="Ethernet23/1")
        iface2.add_trunk_vlan(1001)
        cu.add_iface(iface2)

        self.switch.apply_config_update(cu)
        self.switch._api.set.assert_called_with(update=expected_update_config, replace=[],
                                                delete=expected_delete_config)

    def test_remove_everything(self):
        def _get(prefix):
            if prefix == 'interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis':
                return {'arista-exp-eos-vxlan:vlan-to-vni': [
                        {'vlan': 1000, 'vni': 232323},
                        {'vlan': 1001, 'vni': 424242}]}
            elif prefix == 'lacp':
                return {'openconfig-lacp:interfaces': {'interface': []}}
            elif prefix == 'interfaces':
                return {
                    'openconfig-interfaces:interface': [
                        {'name': 'Port-Channel23', 'config': {'name': 'Port-Channel23'},
                         'openconfig-if-aggregate:aggregation': {
                            'openconfig-vlan:switched-vlan': {'config': {
                                'interface-mode': 'TRUNK', 'native-vlan': 1,
                                'trunk-vlans': [1000, 2002, 2005, '2323..2327']}}}},
                        {'name': 'Ethernet4/1', 'config': {'name': 'Ethernet4/1'},
                         'openconfig-if-ethernet:ethernet': {
                            'openconfig-vlan:switched-vlan': {'config': {
                                'interface-mode': 'TRUNK', 'native-vlan': 1,
                                'trunk-vlans': [1000, 1003]}}}},
                        {'name': 'Ethernet23/1', 'config': {'name': 'Ethernet23/1'},
                         'openconfig-if-ethernet:ethernet': {
                            'openconfig-vlan:switched-vlan': {'config': {
                                'interface-mode': 'TRUNK', 'native-vlan': 1,
                                'trunk-vlans': ['999..1002']}}}},
                    ]}
        self.switch._api.get.side_effect = _get

        expected_config = {
            'delete': [
                'network-instances/network-instance[name=default]/vlans/vlan[vlan-id=1000]',
                'network-instances/network-instance[name=default]/vlans/vlan[vlan-id=1001]',
                'interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis/'
                'vlan-to-vni[vlan=1000]',
                'interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis/'
                'vlan-to-vni[vlan=1001]',
                'arista/eos/arista-exp-eos-evpn:evpn/evpn-instances/evpn-instance[name=1000]',
                'interfaces/interface[name=Port-Channel23]/aggregation/switched-vlan/config/native-vlan',
                'interfaces/interface[name=Port-Channel23]/aggregation/switched-vlan/vlan-translation/'
                'egress[translation-key=1000]',
                'interfaces/interface[name=Port-Channel23]/aggregation/switched-vlan/vlan-translation/'
                'ingress[translation-key=2323]',
                'interfaces/interface[name=Port-Channel23]/aggregation/switched-vlan/vlan-translation/'
                'egress[translation-key=1001]',
                'interfaces/interface[name=Port-Channel23]/aggregation/switched-vlan/vlan-translation/'
                'ingress[translation-key=1337]',
                'interfaces/interface[name=Ethernet4/1]/ethernet/switched-vlan/config/native-vlan',
                'interfaces/interface[name=Ethernet4/1]/ethernet/switched-vlan/vlan-translation/'
                'egress[translation-key=1000]',
                'interfaces/interface[name=Ethernet4/1]/ethernet/switched-vlan/vlan-translation/'
                'ingress[translation-key=2323]',
                'interfaces/interface[name=Ethernet4/1]/ethernet/switched-vlan/vlan-translation/'
                'egress[translation-key=1001]',
                'interfaces/interface[name=Ethernet4/1]/ethernet/switched-vlan/vlan-translation/'
                'ingress[translation-key=1337]',
                'interfaces/interface[name=Ethernet4/2]/ethernet/switched-vlan/config/native-vlan',
                'interfaces/interface[name=Ethernet4/2]/ethernet/switched-vlan/vlan-translation/'
                'egress[translation-key=1000]',
                'interfaces/interface[name=Ethernet4/2]/ethernet/switched-vlan/vlan-translation/'
                'ingress[translation-key=2323]',
                'interfaces/interface[name=Ethernet4/2]/ethernet/switched-vlan/vlan-translation/'
                'egress[translation-key=1001]',
                'interfaces/interface[name=Ethernet4/2]/ethernet/switched-vlan/vlan-translation/'
                'ingress[translation-key=1337]'],
            'replace': [
                ('interfaces/interface[name=Port-Channel23]/aggregation/switched-vlan/config/trunk-vlans',
                 ['2002', '2005', '2323..2327']),
                ('interfaces/interface[name=Ethernet4/1]/ethernet/switched-vlan/config/trunk-vlans', ['1003']),
                ('interfaces/interface[name=Ethernet4/2]/ethernet/switched-vlan/config/trunk-vlans', []),
                ('interfaces/interface[name=Ethernet23/1]/ethernet/switched-vlan/config/trunk-vlans',
                 ['999..1000', '1002'])],
            'update': []}

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.remove)
        # vlans
        cu.add_vlan(1000, "nest")
        cu.add_vlan(1001, "basket")

        # vxlan maps
        cu.add_vxlan_map(232323, 1000)
        cu.add_vxlan_map(424242, 1001)
        cu.add_vxlan_map(343434, 1337)

        # bgp stuff / vlans
        cu.bgp = messages.BGP(asn="65000", asn_region="65123", switchgroup_id=4223)
        cu.bgp.add_vlan(1000, 232323)

        # interfaces
        iface1 = messages.IfaceConfig(name="Port-Channel23", portchannel_id=23, native_vlan=1000,
                                      members=["Ethernet4/1", "Ethernet4/2"])
        iface1.add_trunk_vlan(1000)
        iface1.add_trunk_vlan(1001)
        iface1.add_vlan_translation(1000, 2323)
        iface1.add_vlan_translation(1001, 1337)
        cu.add_iface(iface1)

        iface2 = messages.IfaceConfig(name="Ethernet23/1")
        iface2.add_trunk_vlan(1001)
        cu.add_iface(iface2)

        self.switch.apply_config_update(cu)
        self.switch._api.set.assert_called_with(**expected_config)

    def test_add_vlan_map_with_existing(self):
        def _get(prefix):
            if prefix == 'interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis':
                return {'arista-exp-eos-vxlan:vlan-to-vni': [
                        {'vlan': 2000, 'vni': 31337},
                        {'vlan': 2500, 'vni': 232323},
                        {'vlan': 2, 'vni': 3}]}
        self.switch._api.get.side_effect = _get

        expected_config = {
            'delete': ['interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis/'
                       'vlan-to-vni[vlan=2500]'],
            'replace': [],
            'update': [('interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis',
                        {'vlan-to-vni': [{'vlan': 1000, 'vni': 232323}]}),
                       ('interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis',
                        {'vlan-to-vni': [{'vlan': 2000, 'vni': 424242}]})]}

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.add)
        cu.add_vxlan_map(232323, 1000)
        cu.add_vxlan_map(424242, 2000)

        self.switch.apply_config_update(cu)
        self.switch._api.set.assert_called_with(**expected_config)

    def test_replace_trunk_vlans(self):
        expected_config = {
            'delete': [],
            'replace': [('interfaces/interface[name=Ethernet23/1]/ethernet',
                         {'switched-vlan': {'config': {'interface-mode': 'TRUNK',
                                                       'trunk-vlans': ['1001']}}})],
            'update': []}

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.replace)
        iface = messages.IfaceConfig(name="Ethernet23/1")
        iface.add_trunk_vlan(1001)
        cu.add_iface(iface)

        self.switch.apply_config_update(cu)
        self.switch._api.set.assert_called_with(**expected_config)

    def test_replace_vlans(self):
        expected_config = {
            'replace': [('network-instances/network-instance[name=default]/vlans',
                         {'vlan': [{'config': {'name': 'nest', 'vlan-id': 1000},
                                    'vlan-id': 1000},
                                   {'config': {'name': 'basket', 'vlan-id': 1001},
                                    'vlan-id': 1001}]})],
            'update': [],
            'delete': [],

        }

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.replace)
        # vlans
        cu.add_vlan(1000, "nest")
        cu.add_vlan(1001, "basket")

        self.switch.apply_config_update(cu)
        self.switch._api.set.assert_called_with(**expected_config)

    def test_update_vxlan_maps(self):
        def _get(prefix):
            if prefix == 'interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis':
                return {'arista-exp-eos-vxlan:vlan-to-vni': [
                        {'vlan': 42, 'vni': 23},
                        {'vlan': 444, 'vni': 2000},
                        {'vlan': 2000, 'vni': 232323}]}
        self.switch._api.get.side_effect = _get

        expected_config = {
            'delete': [
                'interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis/'
                'vlan-to-vni[vlan=2000]'
            ],
            'update': [('interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis',
                        {'vlan-to-vni': [{'vlan': 42, 'vni': 23}]}),
                       ('interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis',
                        {'vlan-to-vni': [{'vlan': 1337, 'vni': 232323}]})],
            'replace': [],
        }

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.add)
        # vlans
        cu.add_vxlan_map(23, 42)
        cu.add_vxlan_map(232323, 1337)

        self.switch.apply_config_update(cu)
        self.switch._api.set.assert_called_with(**expected_config)

    def test_update_vlan_translations(self):
        def _get(prefix):
            if prefix == 'interfaces':
                return {
                    'openconfig-interfaces:interface': [
                        {'name': 'Port-Channel23', 'config': {'name': 'Port-Channel23'},
                         'openconfig-if-aggregate:aggregation': {
                            'openconfig-vlan:switched-vlan': {
                                'vlan-translation:vlan-translation': {
                                    'egress': [{'translation-key': 888,
                                                'config': {'translation-key': 888, 'bridging-vlan': 42}},
                                               {'translation-key': 1000,
                                                'config': {'translation-key': 1000, 'bridging-vlan': 2000}}],
                                    'ingress': [{'translation-key': 777,
                                                 'config': {'translation-key': 777, 'bridging-vlan': 23}},
                                                {'translation-key': 2000,
                                                 'config': {'translation-key': 2000, 'bridging-vlan': 1000}}],
                                }}}},
                        {'name': 'Ethernet23/1', 'config': {'name': 'Ethernet23/1'},
                         'openconfig-if-ethernet:ethernet': {
                            'openconfig-vlan:switched-vlan': {
                                'vlan-translation:vlan-translation': {
                                    'egress': [{'translation-key': 889,
                                                'config': {'translation-key': 889, 'bridging-vlan': 42}}],
                                    'ingress': [{'translation-key': 778,
                                                 'config': {'translation-key': 778, 'bridging-vlan': 23}}],
                                }}}}]}
        self.switch._api.get.side_effect = _get

        expected_config = {
            'delete': [
                'interfaces/interface[name=Port-Channel23]/aggregation/switched-vlan/vlan-translation/'
                'ingress[translation-key=777]',
                'interfaces/interface[name=Port-Channel23]/aggregation/switched-vlan/vlan-translation/'
                'egress[translation-key=888]',
                'interfaces/interface[name=Ethernet23/1]/ethernet/switched-vlan/vlan-translation/'
                'ingress[translation-key=778]',
                'interfaces/interface[name=Ethernet23/1]/ethernet/switched-vlan/vlan-translation/'
                'egress[translation-key=889]',
            ],
            'replace': [],
            'update': [
                ('interfaces/interface[name=Port-Channel23]/aggregation',
                 {'config': {'arista-intf-augments:fallback': 'individual',
                             'arista-intf-augments:mlag': 23,
                             'lag-type': 'LACP'},
                  'switched-vlan': {'config': {'vlan-translation': {'egress': [{'config': {'bridging-vlan': 42,
                                                                                           'translation-key': 23},
                                                                                'translation-key': 23},
                                                                               {'config': {'bridging-vlan': 2000,
                                                                                           'translation-key': 1000},
                                                                                'translation-key': 1000}],
                                                                    'ingress': [{'config': {'bridging-vlan': 23,
                                                                                            'translation-key': 42},
                                                                                 'translation-key': 42},
                                                                                {'config': {'bridging-vlan': 1000,
                                                                                            'translation-key': 2000},
                                                                                 'translation-key': 2000}]}}}}),
                ('interfaces/interface[name=Ethernet23/1]/ethernet',
                 {'config': {'aggregate-id': 'Port-Channel23'},
                  'switched-vlan': {'config': {'vlan-translation': {'egress': [{'config': {'bridging-vlan': 42,
                                                                                           'translation-key': 23},
                                                                                'translation-key': 23},
                                                                               {'config': {'bridging-vlan': 2000,
                                                                                           'translation-key': 1000},
                                                                                'translation-key': 1000}],
                                                                    'ingress': [{'config': {'bridging-vlan': 23,
                                                                                            'translation-key': 42},
                                                                                 'translation-key': 42},
                                                                                {'config': {'bridging-vlan': 1000,
                                                                                            'translation-key': 2000},
                                                                                 'translation-key': 2000}]}}}})]}

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.add)
        iface = messages.IfaceConfig(name="Port-Channel23", portchannel_id=23, members=["Ethernet23/1"])
        iface.add_vlan_translation(23, 42)
        iface.add_vlan_translation(1000, 2000)
        cu.add_iface(iface)

        self.switch.apply_config_update(cu)
        self.switch._api.set.assert_called_with(**expected_config)
        self.switch._api.set.reset_mock()

    def test_replace_bgp_vlans(self):
        expected_config = {
            'replace': [('arista/eos/arista-exp-eos-evpn:evpn/evpn-instances',
                         {'evpn-instance': [{'config': {'name': '1000',
                                                        'route-distinguisher': '4223:232323',
                                                        'redistribute': ['LEARNED']},
                                             'name': '1000',
                                             'route-target': {'config': {'export': ['65123:232323'],
                                                                         'import': ['65123:232323']}},
                                             'vlans': {'vlan': [{'config': {'vlan-id': 1000},
                                                                 'vlan-id': 1000}]}}]})],
            'update': [],
            'delete': [],
        }

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.replace)
        # bgp vlans
        cu.bgp = messages.BGP(asn="65000", asn_region="65123", switchgroup_id=4223)
        cu.bgp.add_vlan(1000, 232323)

        self.switch.apply_config_update(cu)
        self.switch._api.set.assert_called_with(**expected_config)

    def test_bgp_vlans_bgw_mode(self):
        expected_cli_config = {
            'update': [
                ('cli:', 'router bgp 65000'),
                ('cli:', 'vlan 1000'),
                ('cli:', 'rd evpn domain all 4223:232323'),
                ('cli:', 'route-target import evpn domain remote 65123:232323'),
                ('cli:', 'route-target export evpn domain remote 65123:232323'),
                ('cli:', 'exit'),
                ('cli:', 'exit'),
            ],
            'encoding': 'ascii'
        }
        expected_config = {
            'delete': [],
            'replace': [],
            'update': [('arista/eos/arista-exp-eos-evpn:evpn/evpn-instances',
                        {'evpn-instance': [{'config': {'name': '1000', 'redistribute': ['LEARNED']},
                                            'name': '1000',
                                            'route-target': {'config': {'export': ['65123:232323'],
                                                                        'import': ['65123:232323']}},
                                            'vlans': {'vlan': [{'config': {'vlan-id': 1000},
                                                                'vlan-id': 1000}]}}]})]}

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.add)
        # bgp vlans
        cu.bgp = messages.BGP(asn="65000", asn_region="65123", switchgroup_id=4223)
        cu.bgp.add_vlan(1000, 232323, bgw_mode=True)

        self.switch.apply_config_update(cu)
        self.switch._api.set.assert_has_calls([mock.call(**expected_cli_config), mock.call(**expected_config)])


class TestEOSSwitch(base.TestCase):
    def setUp(self):
        super().setUp()
        drv_conf = cfix.make_config(global_config=cfix.make_global_config(asn_region=65130))
        _override_driver_config(drv_conf)
        cfg_switch = config_driver.Switch(name="seagull-sw1", host="127.0.0.1", platform=cc_const.PLATFORM_EOS,
                                          user="seagulladm", password="KRAKRAKRA", bgp_source_ip="1.1.1.1")
        self.switch = EOSSwitch(cfg_switch)
        self.switch._api = mock.Mock()
        self.switch._api.execute.return_value = {'result': [{}]}

    def test_get_switch_config(self):
        def _get(prefix):
            if prefix == 'network-instances/network-instance[name=default]/vlans':
                return {
                    'openconfig-network-instance:vlan': [
                        {'config': {'vlan-id': 2121, 'name': 'b226a569-e0ed-4d24-b943-c7183288'},
                         'vlan-id': 2121}]}
            elif prefix == 'interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis':
                return {'arista-exp-eos-vxlan:vlan-to-vni': [{'vlan': 2121, 'vni': 31337}]}
            elif prefix == ('network-instances/network-instance[name=default]/protocols/protocol[name=BGP]/'
                            'bgp/global/config/as'):
                return 4268363793
            elif prefix == 'arista/eos/arista-exp-eos-evpn:evpn/evpn-instances':
                return {
                    'arista-exp-eos-evpn:evpn-instance': [
                        {'config': {'name': '2000',
                                    'route-distinguisher': '4223:10091'},
                         'route-target': {'config': {'export': ['65130:10091'], 'import': ['65130:10091']}},
                         'name': "2000"}
                    ]}
            elif prefix == 'lacp':
                return {
                    'openconfig-lacp:interfaces': {'interface': [
                        {'config': {'name': 'Port-Channel109'},
                         'name': 'Port-Channel109',
                         'members': {'member': [{'interface': 'Ethernet9/1'}]}},
                    ]}}
            elif prefix == 'interfaces':
                return {
                    'openconfig-interfaces:interface': [
                        {'name': 'Port-Channel109', 'config': {'name': 'Port-Channel109'},
                         'openconfig-if-aggregate:aggregation': {
                            'openconfig-vlan:switched-vlan': {'config': {
                                'interface-mode': 'TRUNK', 'native-vlan': 2121,
                                'trunk-vlans': ['2000..2002']}}}},
                        {'name': 'Ethernet1/1', 'config': {'name': 'Ethernet1/1'},
                         'openconfig-if-ethernet:ethernet': {
                            'openconfig-vlan:switched-vlan': {
                                'config': {
                                    'interface-mode': 'TRUNK', 'native-vlan': 1,
                                    'trunk-vlans': []},
                                'vlan-translation:vlan-translation': {
                                    'egress': [{'translation-key': 3001,
                                                'config': {'translation-key': 3001, 'bridging-vlan': 2000}}],
                                    'ingress': [{'translation-key': 2000,
                                                 'config': {'translation-key': 2000, 'bridging-vlan': 3001}}],
                                }}}}]}
            elif prefix == 'network-instances':
                return {'openconfig-network-instance:network-instance': [
                    {'config': {'type': 'scratchingpost'}},
                    {'config': {'enabled': True,
                                'enabled-address-families': ['openconfig-types:IPV4'],
                                'name': 'VRF-CASPIAN-TERN',
                                'route-distinguisher': '65130:666',
                                'type': 'openconfig-network-instance-types:L3VRF'},
                     'interfaces': {'interface': [{'config': {'id': 'Vlan2666',
                                                              'interface': 'Vlan2666'},
                                                   'id': 'Vlan2666',
                                                   'state': {'id': 'Vlan2666',
                                                             'interface': 'Vlan2666'}}]},
                     'name': 'VRF-CASPIAN-TERN',
                     'protocols': {'protocol': [
                         {'config': {'identifier': 'openconfig-policy-types:DIRECTLY_CONNECTED',
                                     'name': 'DIRECTLY_CONNECTED'},
                          'identifier': 'openconfig-policy-types:DIRECTLY_CONNECTED',
                          'name': 'DIRECTLY_CONNECTED'},
                         {'bgp': {'global': {'afi-safis': {'afi-safi': [
                             {'afi-safi-name': 'openconfig-bgp-types:IPV6_UNICAST',
                              'config': {'afi-safi-name': 'openconfig-bgp-types:IPV6_UNICAST'},
                              'state': {'afi-safi-name': 'openconfig-bgp-types:IPV6_UNICAST'}},
                             {'afi-safi-name': 'openconfig-bgp-types:IPV4_UNICAST',
                              'arista-bgp-augments:aggregate-addresses': {'aggregate-address': [
                                  {'aggregate-address': '10.100.1.0/24',
                                   'config': {'aggregate-address': '10.100.1.0/24',
                                              'attribute-map': 'RM-CC-LOL'}}]},
                              'config': {'afi-safi-name': 'openconfig-bgp-types:IPV4_UNICAST'},
                              'state': {'afi-safi-name': 'openconfig-bgp-types:IPV4_UNICAST'}}]},
                             'arista-bgp-augments:evpn': {'export-target': ['333:444'],
                                                          'import-target': ['111:222']},
                             'state': {'router-id': '4.1.13.1'}}},
                          'config': {'identifier': 'openconfig-policy-types:BGP',
                                     'name': 'BGP'},
                          'identifier': 'openconfig-policy-types:BGP',
                          'name': 'BGP'}]}}



                ]}
            elif prefix == 'interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vrf-to-vnis':
                return {'arista-exp-eos-vxlan:vrf-to-vni': [
                    {'vni': 232323, 'vrf': 'VRF-LAUGHING-GULL'},
                    {'vni': 31337, 'vrf': 'VRF-CASPIAN-TERN'},
                ]}
            elif prefix == 'routing-policy/policy-definitions':
                return {'openconfig-routing-policy:policy-definition': []}
            raise ValueError(f"unmapped command: {prefix}")
        self.switch._api.get.side_effect = _get

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.add)
        cu.add_vlan(2121, "b226a569-e0ed-4d24-b943-c7183288")
        cu.add_vxlan_map(31337, 2121)
        cu.bgp = messages.BGP(asn="65130.4113", asn_region=65130, switchgroup_id=4223)
        cu.bgp.add_vlan(2000, 10091, bgw_mode=False)
        cu.bgp.switchgroup_id = None  # not needed for comparison (not fetched from switch)
        bgpvrf = messages.BGPVRF(name="VRF-CASPIAN-TERN", rd="65130:666",
                                 rt_imports_evpn=["111:222"], rt_exports_evpn=["333:444"],
                                 aggregates=[messages.BGPVRFAggregate(network="10.100.1.0/24", route_map="RM-CC-LOL")],
                                 networks=[])
        cu.bgp.vrfs = [bgpvrf]
        cu.add_vrf_vxlan_map("VRF-LAUGHING-GULL", 232323)
        cu.add_vrf_vxlan_map("VRF-CASPIAN-TERN", 31337)
        iface = messages.IfaceConfig(name="Port-Channel109", members=["Ethernet9/1"],
                                     trunk_vlans=[2000, 2001, 2002], native_vlan=2121, portchannel_id=109)
        cu.add_iface(iface)
        iface = messages.IfaceConfig(name="Ethernet1/1")
        iface.add_vlan_translation(2000, 3001)
        cu.add_iface(iface)
        cu.sort()

        config = self.switch.get_config()
        config.sort()
        self.assertEqual(cu.dict(exclude_unset=True, exclude_defaults=True),
                         config.dict(exclude_unset=True, exclude_defaults=True))

    def test_compress_vlan_list(self):
        self.assertEqual([], self.switch._compress_vlan_list([]))
        self.assertEqual(["1..4"], self.switch._compress_vlan_list([1, 2, 3, 4]))
        self.assertEqual(["1", "3", "5", "7"], self.switch._compress_vlan_list([1, 3, 5, 7]))
        self.assertEqual(["1..3", "5..7"], self.switch._compress_vlan_list([1, 2, 3, 5, 6, 7]))
        self.assertEqual(["1", "3..5", "7..8", "10"], self.switch._compress_vlan_list([1, 3, 4, 5, 7, 8, 10]))
        self.assertEqual(["1..1000"], self.switch._compress_vlan_list(list(range(1, 1001))))
        self.assertEqual(["1000..1002"], self.switch._compress_vlan_list([1002, 1001, 1000]))

        # input vlan list is expected to be uniq, but this method will do deduplication anyway, so let's test it
        self.assertEqual(["1000..1002", "1007"],
                         self.switch._compress_vlan_list([1002, 1001, 1000, 1001, 1000, 1002, 1007, 1007]))
