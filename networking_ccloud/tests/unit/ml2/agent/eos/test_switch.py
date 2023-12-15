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

from neutron_lib import rpc as n_rpc
from oslo_config import cfg

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

        cfg.CONF.set_override('prometheus_enabled', False, group='ml2_cc_fabric_agent')
        with mock.patch.object(n_rpc, 'get_client'):
            self.switch = EOSSwitch(cfg_switch, 65130, 'a', set([100]) | set(range(2000, 3000)), 'cc-eos-switch-agent')
        self.switch._api = mock.Mock()

    def test_add_vlans(self):
        expected_update = [
            ('network-instances/network-instance[name=default]/vlans',
             {'vlan': [
                 {'vlan-id': 1000, 'config': {'name': 'nest', 'vlan-id': 1000}},
                 {'vlan-id': 1001, 'config': {'name': 'basket', 'vlan-id': 1001}},
                 {'vlan-id': 1002, 'config': {'name': '36a4e83f301d47da994b40ba080a42f5', 'vlan-id': 1002}}]})]

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.add)
        cu.add_vlan(1000, "nest")
        cu.add_vlan(1001, "basket")
        cu.add_vlan(1002, "36a4e83f-301d-47da-994b-40ba080a42f5")
        self.switch.apply_config_update(cu).result()
        self.switch._api.set.assert_called_with(update=expected_update, delete=[], replace=[])

    def test_add_everything(self):
        def _get(prefix, unpack=True):
            if prefix == 'interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis':
                return {'arista-exp-eos-vxlan:vlan-to-vni': [{'vlan': 1337, 'vni': 232323}]}
            elif prefix == 'interfaces':
                return {
                    'openconfig-interfaces:interface': [
                        {'name': 'Vlan2337', 'config': {'name': 'Vlan2337', 'type': 'l3ipvlan'},
                         'arista-varp': {'virtual-address': {'config': {'ip': '3.4.3.5/24', 'prefix-length': 24}}}},
                    ]}
            elif not unpack and prefix == 'eos_native:Sysdb/ip/config/ipIntfConfig':
                return {'notification': [
                    {'prefix': 'foo'},
                    {'prefix': 'Sysdb/ip/config/ipIntfConfig/Vlan2337/virtualSecondaryWithMask',
                     'update': [{'path': '1.1.1.1/24', 'val': True}, {'path': '2.2.2.2/24', 'val': True}]},
                ]}
            raise ValueError(f"unmapped command: {prefix}")
        self.switch._api.get.side_effect = _get

        expected_update_config = [
            ('network-instances/network-instance[name=default]/vlans',
             {'vlan': [{'config': {'name': 'nest', 'vlan-id': 1000}, 'vlan-id': 1000},
                       {'config': {'name': 'basket', 'vlan-id': 1001}, 'vlan-id': 1001}]}),
            ('interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis',
             {'vlan-to-vni': [{'vlan': 1000, 'vni': 232323}, {'vlan': 1001, 'vni': 424242}]}),
            ('arista/eos/arista-exp-eos-evpn:evpn/evpn-instances/evpn-instance[name=1000]',
             {'config': {'name': '1000',
                         'route-distinguisher': '4223:232323',
                         'redistribute': ['LEARNED', 'ROUTER_MAC', 'HOST_ROUTE']},
              'name': '1000',
              'route-target': {'config': {'export': ['1:232323'],
                                          'import': ['1:232323']}},
              'vlans': {'vlan': [{'config': {'vlan-id': 1000},
                                  'vlan-id': 1000}]}}),
            ('network-instances/network-instance[name=CC-SEAGULL]/protocols/protocol[name=BGP]/bgp/global/'
             'afi-safis/afi-safi[afi-safi-name=openconfig-bgp-types:IPV4_UNICAST]/aggregate-addresses', {
                 'aggregate-address': [
                     {'aggregate-address': '8.8.8.0/24',
                      'config': {'aggregate-address': '8.8.8.0/24', 'attribute-map': 'RM-CC-SEAGULL-AGGREGATE'}},
                     {'aggregate-address': '9.9.9.0/24',
                      'config': {'aggregate-address': '9.9.9.0/24', 'attribute-map': 'RM-CC-SEAGULL-A-AGGREGATE'}}]}),
            ('routing-policy/defined-sets/prefix-sets/prefix-set[name=PL-CC-SEAGULL]',
             {'name': 'PL-CC-SEAGULL', 'config': {'name': 'PL-CC-SEAGULL'}, 'prefixes': {'prefix':
              [{'ip-prefix': '4.4.4.0/24', 'masklength-range': 'exact',
                'config': {'ip-prefix': '4.4.4.0/24', 'masklength-range': 'exact'}}]}}),
            ('routing-policy/defined-sets/prefix-sets/prefix-set[name=PL-CC-SEAGULL-EXTERNAL]',
             {'name': 'PL-CC-SEAGULL-EXTERNAL', 'config': {'name': 'PL-CC-SEAGULL-EXTERNAL'}, 'prefixes': {'prefix':
              [{'ip-prefix': '5.5.5.0/24', 'masklength-range': 'exact',
                'config': {'ip-prefix': '5.5.5.0/24', 'masklength-range': 'exact'}}]}}),
            ('routing-policy/defined-sets/prefix-sets/prefix-set[name=PL-CC-SEAGULL-A]',
             {'name': 'PL-CC-SEAGULL-A', 'config': {'name': 'PL-CC-SEAGULL-A'}, 'prefixes': {'prefix':
              [{'ip-prefix': '6.6.6.0/24', 'masklength-range': 'exact',
                'config': {'ip-prefix': '6.6.6.0/24', 'masklength-range': 'exact'}}]}}),
            ('routing-policy/defined-sets/prefix-sets/prefix-set[name=PL-CC-SEAGULL-A-EXTERNAL]',
             {'name': 'PL-CC-SEAGULL-A-EXTERNAL', 'config': {'name': 'PL-CC-SEAGULL-A-EXTERNAL'}, 'prefixes': {'prefix':
              [{'ip-prefix': '7.7.7.0/24', 'masklength-range': 'exact',
                'config': {'ip-prefix': '7.7.7.0/24', 'masklength-range': 'exact'}},
               {'ip-prefix': '10.10.10.0/24', 'masklength-range': 'exact',
                'config': {'ip-prefix': '10.10.10.0/24', 'masklength-range': 'exact'}}]}}),
            ('interfaces/interface[name=Port-Channel23]', {
                'config': {
                    'name': 'Port-Channel23',
                    'type': 'iana-if-type:ieee8023adLag'
                },
                'name': 'Port-Channel23',
                'aggregation': {
                    'config': {
                        'fallback': 'individual',
                        'mlag': 23,
                        'fallback-timeout': 50,
                        'lag-type': 'LACP',
                    },
                    'switched-vlan': {
                        'config': {
                            'interface-mode': 'TRUNK',
                            'native-vlan': 1000,
                            'trunk-vlans': ['1000..1001'],
                        },
                        'vlan-translation': {
                            'egress': [{
                                'config': {
                                    'bridging-vlan': 2323,
                                    'translation-key': 1000
                                },
                                'translation-key': 1000
                            }, {
                                'config': {
                                    'bridging-vlan': 1337,
                                    'translation-key': 1001
                                },
                                'translation-key': 1001
                            }],
                            'ingress': [{
                                'config': {
                                    'bridging-vlan': 1000,
                                    'translation-key': 2323
                                },
                                'translation-key': 2323
                            }, {
                                'config': {
                                    'bridging-vlan': 1001,
                                    'translation-key': 1337
                                },
                                'translation-key': 1337
                            }]
                        }
                    }
                }
            }),
            ('interfaces/interface[name=Ethernet4/1]/ethernet',
             {'config': {'aggregate-id': 'Port-Channel23'},
              'switched-vlan': {'config': {'interface-mode': 'TRUNK',
                                           'native-vlan': 1000,
                                           'trunk-vlans': ['1000..1001']},
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
                                                                  'translation-key': 1337}]}}}),
            ('interfaces/interface[name=Ethernet4/2]/ethernet',
             {'config': {'aggregate-id': 'Port-Channel23'},
              'switched-vlan': {'config': {'interface-mode': 'TRUNK',
                                           'native-vlan': 1000,
                                           'trunk-vlans': ['1000..1001']},
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
                                                                  'translation-key': 1337}]}}}),
            ('interfaces/interface[name=Port-Channel42]', {
                'config': {
                    'name': 'Port-Channel42',
                    'type': 'iana-if-type:ieee8023adLag'
                },
                'name': 'Port-Channel42',
                'aggregation': {
                    'config': {
                        'fallback': 'individual',
                        'mlag': 42,
                        'fallback-timeout': 50,
                        'lag-type': 'LACP',
                    },
                    'switched-vlan': {
                        'config': {
                            'interface-mode': 'TRUNK',
                            'native-vlan': 1000,
                            'trunk-vlans': ['667'],
                        },
                    }
                }
            }),
            ('interfaces/interface[name=Ethernet5/1]/ethernet',
             {'config': {'aggregate-id': 'Port-Channel42',
                         'port-speed': 'SPEED_25GB', 'auto-negotiate': False, 'duplex-mode': 'FULL'},
              'switched-vlan': {'config': {'interface-mode': 'TRUNK',
                                           'native-vlan': 1000,
                                           'trunk-vlans': ['667']}}}),
            ('interfaces/interface[name=Ethernet5/2]/ethernet',
             {'config': {'aggregate-id': 'Port-Channel42',
                         'port-speed': 'SPEED_25GB', 'auto-negotiate': False, 'duplex-mode': 'FULL'},
              'switched-vlan': {'config': {'interface-mode': 'TRUNK',
                                           'native-vlan': 1000,
                                           'trunk-vlans': ['667']}}}),
            ('interfaces/interface[name=Ethernet23/1]/ethernet',
             {'switched-vlan': {'config': {'interface-mode': 'TRUNK',
                                           'trunk-vlans': ['1001']}}}),
            ('interfaces/interface[name=Ethernet23/2]/ethernet',
             {'config': {'port-speed': 'SPEED_100GB', 'auto-negotiate': False, 'duplex-mode': 'FULL'},
              'switched-vlan': {'config': {'interface-mode': 'TRUNK',
                                           'trunk-vlans': ['1001']}}}),
            ('interfaces/interface[name=Vlan2337]',
             {'name': 'Vlan2337', 'config': {'name': 'Vlan2337', 'type': 'l3ipvlan'},
              'arista-varp': {'virtual-address': {'config': {'ip': '1.1.1.1', 'prefix-length': 24}}}}),
            ('network-instances/network-instance[name=CC-SEAGULL]/interfaces',
             {'interface': [{'id': 'Vlan2337', 'config': {'id': 'Vlan2337'}}]}),
        ]
        expected_delete_config = [
            "interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis/"
            "vlan-to-vni[vlan=1337]"
        ]
        expected_cli_config = {
            'update': [
                ('cli:', 'interface Vlan2337'),
                ('cli:', 'no ip address virtual 1.1.1.1/24 secondary'),
                ('cli:', 'ip address virtual 2.2.2.2/24 secondary'),
                ('cli:', 'ip address virtual 3.3.3.3/24 secondary'),
                ('cli:', 'exit'),
            ],
            'encoding': 'ascii'
        }

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.add)
        # vlans
        cu.add_vlan(1000, "nest")
        cu.add_vlan(1001, "basket")

        # vxlan maps
        cu.add_vxlan_map(232323, 1000)
        cu.add_vxlan_map(424242, 1001)

        # bgp stuff / vlans
        cu.bgp = messages.BGP(asn="65000", asn_region="65123", switchgroup_id=4223)
        cu.bgp.add_vlan(1000, 232323, 1)

        # interfaces
        pc1 = messages.IfaceConfig(name="Port-Channel23", portchannel_id=23, native_vlan=1000,
                                   members=["Ethernet4/1", "Ethernet4/2"])
        pc1.add_trunk_vlan(1000)
        pc1.add_trunk_vlan(1001)
        pc1.add_vlan_translation(1000, 2323)
        pc1.add_vlan_translation(1001, 1337)
        cu.add_iface(pc1)

        pc2 = messages.IfaceConfig(name="Port-Channel42", portchannel_id=42, native_vlan=1000,
                                   members=["Ethernet5/1", "Ethernet5/2"], speed='25g')
        pc2.add_trunk_vlan(667)
        cu.add_iface(pc2)

        iface1 = messages.IfaceConfig(name="Ethernet23/1")
        iface1.add_trunk_vlan(1001)
        cu.add_iface(iface1)

        iface2 = messages.IfaceConfig(name="Ethernet23/2")
        iface2.add_trunk_vlan(1001)
        iface2.speed = "100g"
        cu.add_iface(iface2)

        # vlan iface + vrf
        cu.add_vlan_iface(vlan=2337, vrf="CC-SEAGULL", primary_ip="1.1.1.1/24",
                          secondary_ips=["2.2.2.2/24", "3.3.3.3/24"])
        vrf = cu.bgp.get_or_create_vrf("CC-SEAGULL")
        vrf.add_networks([
            messages.BGPVRFNetwork(network="4.4.4.0/24", az_local=False, ext_announcable=False),
            messages.BGPVRFNetwork(network="5.5.5.0/24", az_local=False, ext_announcable=True),
            messages.BGPVRFNetwork(network="6.6.6.0/24", az_local=True, ext_announcable=False),
            messages.BGPVRFNetwork(network="7.7.7.0/24", az_local=True, ext_announcable=True),
            messages.BGPVRFNetwork(network="10.10.10.0/24", az_local=True, ext_announcable=True),
        ])
        vrf.add_aggregates([
            messages.BGPVRFAggregate(network="8.8.8.0/24", az_local=False),
            messages.BGPVRFAggregate(network="9.9.9.0/24", az_local=True),
        ])

        self.switch.apply_config_update(cu).result()
        self.switch._api.set.assert_has_calls([
            mock.call(**expected_cli_config),
            mock.call(update=expected_update_config, replace=[], delete=expected_delete_config)])
        self.switch._api.set.assert_called_with(update=expected_update_config, replace=[],
                                                delete=expected_delete_config)

    def test_remove_everything(self):
        def _get(prefix, unpack=True):
            if prefix == 'interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis':
                return {'arista-exp-eos-vxlan:vlan-to-vni': [
                        {'vlan': 1000, 'vni': 171717},
                        {'vlan': 2000, 'vni': 232323},
                        {'vlan': 2001, 'vni': 424242}]}
            elif prefix == 'lacp':
                return {'openconfig-lacp:interfaces': {'interface': []}}
            elif prefix == 'interfaces':
                return {
                    'openconfig-interfaces:interface': [
                        {'name': 'Port-Channel23', 'config': {'name': 'Port-Channel23',
                                                              'type': 'iana-if-type:ieee8023adLag'},
                         'openconfig-if-aggregate:aggregation': {
                            'openconfig-vlan:switched-vlan': {'config': {
                                'interface-mode': 'TRUNK', 'native-vlan': 1,
                                'trunk-vlans': [2000, 2002, 2005, '2323..2327']}}}},
                        {'name': 'Ethernet4/1', 'config': {'name': 'Ethernet4/1',
                                                           'type': 'iana-if-type:ethernetCsmacd'},
                         'openconfig-if-ethernet:ethernet': {
                            'openconfig-vlan:switched-vlan': {'config': {
                                'interface-mode': 'TRUNK', 'native-vlan': 1,
                                'trunk-vlans': [2000, 2003]}}}},
                        {'name': 'Ethernet23/1', 'config': {'name': 'Ethernet23/1',
                                                            'type': 'iana-if-type:ethernetCsmacd'},
                         'openconfig-if-ethernet:ethernet': {
                            'openconfig-vlan:switched-vlan': {'config': {
                                'interface-mode': 'TRUNK', 'native-vlan': 1,
                                'trunk-vlans': ['1999..2002']}}}},
                    ]}
            elif not unpack and prefix == 'eos_native:Sysdb/ip/config/ipIntfConfig':
                return {'notification': [
                    {'prefix': 'foo'},
                    {'prefix': 'Sysdb/ip/config/ipIntfConfig/Vlan2337/virtualSecondaryWithMask',
                     'update': [{'path': '2.2.2.2/24', 'val': True}, {'path': '3.3.3.3/24', 'val': True}]},
                ]}
            raise ValueError(f"unmapped command: {prefix}")
        self.switch._api.get.side_effect = _get

        expected_config = {
            'delete': [
                'network-instances/network-instance[name=default]/vlans/vlan[vlan-id=2000]',
                'network-instances/network-instance[name=default]/vlans/vlan[vlan-id=2001]',
                'interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis/'
                'vlan-to-vni[vlan=2000]',
                'interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis/'
                'vlan-to-vni[vlan=2001]',
                'arista/eos/arista-exp-eos-evpn:evpn/evpn-instances/evpn-instance[name=2000]',
                'routing-policy/defined-sets/prefix-sets/prefix-set[name=PL-CC-SEAGULL]/'
                'prefixes/prefix[ip-prefix=4.4.4.0/24]',
                'routing-policy/defined-sets/prefix-sets/prefix-set[name=PL-CC-SEAGULL-EXTERNAL]/'
                'prefixes/prefix[ip-prefix=5.5.5.0/24]',
                'routing-policy/defined-sets/prefix-sets/prefix-set[name=PL-CC-SEAGULL-A]/'
                'prefixes/prefix[ip-prefix=6.6.6.0/24]',
                'routing-policy/defined-sets/prefix-sets/prefix-set[name=PL-CC-SEAGULL-A-EXTERNAL]/'
                'prefixes/prefix[ip-prefix=7.7.7.0/24]',
                'routing-policy/defined-sets/prefix-sets/prefix-set[name=PL-CC-SEAGULL-A-EXTERNAL]/'
                'prefixes/prefix[ip-prefix=10.10.10.0/24]',
                'network-instances/network-instance[name=CC-SEAGULL]/protocols/protocol[name=BGP]/bgp/global/'
                'afi-safis/afi-safi[afi-safi-name=openconfig-bgp-types:IPV4_UNICAST]/'
                'aggregate-addresses/aggregate-address[aggregate-address=8.8.8.0/24]',
                'network-instances/network-instance[name=CC-SEAGULL]/protocols/protocol[name=BGP]/bgp/global/'
                'afi-safis/afi-safi[afi-safi-name=openconfig-bgp-types:IPV4_UNICAST]/'
                'aggregate-addresses/aggregate-address[aggregate-address=9.9.9.0/24]',
                'interfaces/interface[name=Port-Channel23]/aggregation/switched-vlan/config/native-vlan',
                'interfaces/interface[name=Port-Channel23]/aggregation/switched-vlan/vlan-translation/'
                'egress[translation-key=2000]',
                'interfaces/interface[name=Port-Channel23]/aggregation/switched-vlan/vlan-translation/'
                'ingress[translation-key=2323]',
                'interfaces/interface[name=Port-Channel23]/aggregation/switched-vlan/vlan-translation/'
                'egress[translation-key=2001]',
                'interfaces/interface[name=Port-Channel23]/aggregation/switched-vlan/vlan-translation/'
                'ingress[translation-key=1337]',
                'interfaces/interface[name=Ethernet4/1]/ethernet/switched-vlan/config/native-vlan',
                'interfaces/interface[name=Ethernet4/1]/ethernet/switched-vlan/vlan-translation/'
                'egress[translation-key=2000]',
                'interfaces/interface[name=Ethernet4/1]/ethernet/switched-vlan/vlan-translation/'
                'ingress[translation-key=2323]',
                'interfaces/interface[name=Ethernet4/1]/ethernet/switched-vlan/vlan-translation/'
                'egress[translation-key=2001]',
                'interfaces/interface[name=Ethernet4/1]/ethernet/switched-vlan/vlan-translation/'
                'ingress[translation-key=1337]',
                'interfaces/interface[name=Ethernet4/2]/ethernet/switched-vlan/config/native-vlan',
                'interfaces/interface[name=Ethernet4/2]/ethernet/switched-vlan/vlan-translation/'
                'egress[translation-key=2000]',
                'interfaces/interface[name=Ethernet4/2]/ethernet/switched-vlan/vlan-translation/'
                'ingress[translation-key=2323]',
                'interfaces/interface[name=Ethernet4/2]/ethernet/switched-vlan/vlan-translation/'
                'egress[translation-key=2001]',
                'interfaces/interface[name=Ethernet4/2]/ethernet/switched-vlan/vlan-translation/'
                'ingress[translation-key=1337]',
                'interfaces/interface[name=Vlan2337]'],
            'replace': [
                ('interfaces/interface[name=Port-Channel23]/aggregation/switched-vlan/config/trunk-vlans',
                 ['2002', '2005', '2323..2327']),
                ('interfaces/interface[name=Ethernet4/1]/ethernet/switched-vlan/config/trunk-vlans', ['2003']),
                ('interfaces/interface[name=Ethernet4/2]/ethernet/switched-vlan/config/trunk-vlans', []),
                ('interfaces/interface[name=Ethernet23/1]/ethernet/switched-vlan/config/trunk-vlans',
                 ['1999..2000', '2002'])],
            'update': []}

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.remove)
        # vlans
        cu.add_vlan(2000, "nest")
        cu.add_vlan(2001, "basket")

        # vxlan maps
        cu.add_vxlan_map(232323, 2000)
        cu.add_vxlan_map(424242, 2001)
        cu.add_vxlan_map(343434, 2337)

        # bgp stuff / vlans
        cu.bgp = messages.BGP(asn="65000", asn_region="65123", switchgroup_id=4223)
        cu.bgp.add_vlan(2000, 232323, 1)

        # interfaces
        iface1 = messages.IfaceConfig(name="Port-Channel23", portchannel_id=23, native_vlan=2000,
                                      members=["Ethernet4/1", "Ethernet4/2"])
        iface1.add_trunk_vlan(2000)
        iface1.add_trunk_vlan(2001)
        iface1.add_vlan_translation(2000, 2323)
        iface1.add_vlan_translation(2001, 1337)
        cu.add_iface(iface1)

        iface2 = messages.IfaceConfig(name="Ethernet23/1")
        iface2.add_trunk_vlan(2001)
        cu.add_iface(iface2)

        # vlan iface + vrf
        cu.add_vlan_iface(vlan=2337, vrf="CC-SEAGULL", primary_ip="1.1.1.1/24",
                          secondary_ips=["2.2.2.2/24", "3.3.3.3/24"])
        vrf = cu.bgp.get_or_create_vrf("CC-SEAGULL")
        vrf.add_networks([
            messages.BGPVRFNetwork(network="4.4.4.0/24", az_local=False, ext_announcable=False),
            messages.BGPVRFNetwork(network="5.5.5.0/24", az_local=False, ext_announcable=True),
            messages.BGPVRFNetwork(network="6.6.6.0/24", az_local=True, ext_announcable=False),
            messages.BGPVRFNetwork(network="7.7.7.0/24", az_local=True, ext_announcable=True),
            messages.BGPVRFNetwork(network="10.10.10.0/24", az_local=True, ext_announcable=True),
        ])
        vrf.add_aggregates([
            messages.BGPVRFAggregate(network="8.8.8.0/24", az_local=False),
            messages.BGPVRFAggregate(network="9.9.9.0/24", az_local=True),
        ])

        self.switch.apply_config_update(cu).result()
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
                        {'vlan-to-vni': [{'vlan': 1000, 'vni': 232323}, {'vlan': 2000, 'vni': 424242}]})]}

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.add)
        cu.add_vxlan_map(232323, 1000)
        cu.add_vxlan_map(424242, 2000)

        self.switch.apply_config_update(cu).result()
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

        self.switch.apply_config_update(cu).result()
        self.switch._api.set.assert_called_with(**expected_config)

    def test_replace_vlans(self):
        def _get(prefix, single=True):
            if prefix == 'network-instances/network-instance[name=default]/vlans/vlan/vlan-id' and not single:
                return [100, 104, 1000, 2000, 2500]
            raise ValueError(f"unmapped command: {prefix}")
        self.switch._api.get.side_effect = _get

        expected_config = {
            'update': [('network-instances/network-instance[name=default]/vlans',
                        {'vlan': [{'config': {'name': 'nest', 'vlan-id': 2000},
                                   'vlan-id': 2000},
                                  {'config': {'name': 'basket', 'vlan-id': 2001},
                                   'vlan-id': 2001}]})],
            'replace': [],
            'delete': [
                'network-instances/network-instance[name=default]/vlans/vlan[vlan-id=100]',
                'network-instances/network-instance[name=default]/vlans/vlan[vlan-id=2500]',
            ],

        }

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.replace)
        # vlans
        cu.add_vlan(2000, "nest")
        cu.add_vlan(2001, "basket")

        self.switch.apply_config_update(cu).result()
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
                        {'vlan-to-vni': [{'vlan': 42, 'vni': 23}, {'vlan': 1337, 'vni': 232323}]})],
            'replace': [],
        }

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.add)
        # vlans
        cu.add_vxlan_map(23, 42)
        cu.add_vxlan_map(232323, 1337)

        self.switch.apply_config_update(cu).result()
        self.switch._api.set.assert_called_with(**expected_config)

    def test_replace_vxlan_maps(self):
        def _get(prefix):
            if prefix == 'interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis':
                return {'arista-exp-eos-vxlan:vlan-to-vni': [
                        {'vlan': 42, 'vni': 23},
                        {'vlan': 444, 'vni': 200444},
                        {'vlan': 2000, 'vni': 200333},
                        {'vlan': 2500, 'vni': 232323}]}
        self.switch._api.get.side_effect = _get

        expected_config = {
            'delete': [
                'interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis/'
                'vlan-to-vni[vlan=2500]',
                'interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis/'
                'vlan-to-vni[vlan=444]',
            ],
            'update': [('interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis',
                        {'vlan-to-vni': [{'vlan': 2000, 'vni': 424242}, {'vlan': 2001, 'vni': 200444}]})],
            'replace': [],
        }

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.replace)
        # vlans
        cu.add_vxlan_map(424242, 2000)
        cu.add_vxlan_map(200444, 2001)

        self.switch.apply_config_update(cu).result()
        self.switch._api.set.assert_called_with(**expected_config)

    def test_replace_bgp_vrf_aggregates(self):
        def _get(prefix):
            if prefix == 'routing-policy/defined-sets/prefix-sets':
                return {'openconfig-routing-policy:prefix-set': []}
            elif prefix == 'network-instances':
                return {'openconfig-network-instance:network-instance': [
                    {'config': {'type': 'nesting-ground:seagull'}},
                    {
                        'config': {'type': 'openconfig-network-instance-types:L3VRF'},
                        'name': 'CC-SEAGULL',
                        'protocols': {'protocol': [
                            {'name': 'TERN-TERN-TERN', 'config': {'name': 'TERN-TERN-TERN'}},
                            {
                                'config': {'identifier': 'openconfig-policy-types:BGP', 'name': 'BGP'},
                                'name': 'BGP',
                                'bgp': {'global': {'afi-safis': {'afi-safi': [
                                    {'afi-safi-name': 'openconfig-bgp-types:IPV4_UNICAST',
                                     'config': {'afi-safi-name': 'openconfig-bgp-types:IPV4_UNICAST', 'enabled': True}},
                                    {'afi-safi-name': 'openconfig-bgp-types:IPV4_UNICAST',
                                     'config': {'afi-safi-name': 'openconfig-bgp-types:IPV4_UNICAST', 'enabled': True},
                                     'arista-bgp-augments:aggregate-addresses': {'aggregate-address': [
                                         {'aggregate-address': '12.12.12.0/24', 'config': {
                                             'aggregate-address': '12.12.12.0/24', 'attribute-map': 'TERN-TERN-TERN'}},
                                         {'aggregate-address': '1.1.1.0/24', 'config': {
                                             'aggregate-address': '1.1.1.0/24',
                                             'attribute-map': 'RM-CC-SEAGULL-AGGREGATE'}},
                                         {'aggregate-address': '2.2.2.0/24', 'config': {
                                             'aggregate-address': '2.2.2.0/24',
                                             'attribute-map': 'RM-CC-SEAGULL-AGGREGATE'}},
                                         {'aggregate-address': '3.3.3.0/24', 'config': {
                                             'aggregate-address': '3.3.3.0/24',
                                             'attribute-map': 'TERN-TERN-TERN'}},
                                         {'aggregate-address': '9.9.9.0/24', 'config': {
                                             'aggregate-address': '9.9.9.0/24',
                                             'attribute-map': 'RM-CC-SEAGULL-A-AGGREGATE'}},
                                     ]}},
                                ]}}}
                            },
                        ],
                        }},
                ]}
            raise ValueError(f"unmapped command: {prefix}")
        self.switch._api.get.side_effect = _get

        expected_config = {
            'delete': [
                'network-instances/network-instance[name=CC-SEAGULL]/protocols/protocol[name=BGP]/bgp/global/'
                'afi-safis/afi-safi[afi-safi-name=openconfig-bgp-types:IPV4_UNICAST]/'
                'aggregate-addresses/aggregate-address[aggregate-address=1.1.1.0/24]',
                'network-instances/network-instance[name=CC-SEAGULL]/protocols/protocol[name=BGP]/bgp/global/'
                'afi-safis/afi-safi[afi-safi-name=openconfig-bgp-types:IPV4_UNICAST]/'
                'aggregate-addresses/aggregate-address[aggregate-address=2.2.2.0/24]',
            ],
            'replace': [
                ('routing-policy/defined-sets/prefix-sets/prefix-set[name=PL-CC-SEAGULL]',
                 {'name': 'PL-CC-SEAGULL', 'config': {'name': 'PL-CC-SEAGULL'},
                  'prefixes': {'prefix': []}}),
                ('routing-policy/defined-sets/prefix-sets/prefix-set[name=PL-CC-SEAGULL-EXTERNAL]',
                 {'name': 'PL-CC-SEAGULL-EXTERNAL', 'config': {'name': 'PL-CC-SEAGULL-EXTERNAL'},
                  'prefixes': {'prefix': []}}),
                ('routing-policy/defined-sets/prefix-sets/prefix-set[name=PL-CC-SEAGULL-A]',
                 {'name': 'PL-CC-SEAGULL-A', 'config': {'name': 'PL-CC-SEAGULL-A'},
                  'prefixes': {'prefix': []}}),
                ('routing-policy/defined-sets/prefix-sets/prefix-set[name=PL-CC-SEAGULL-A-EXTERNAL]',
                 {'name': 'PL-CC-SEAGULL-A-EXTERNAL', 'config': {'name': 'PL-CC-SEAGULL-A-EXTERNAL'},
                  'prefixes': {'prefix': []}}),
            ],
            'update': [
                ('network-instances/network-instance[name=CC-SEAGULL]/protocols/protocol[name=BGP]/bgp/global/'
                 'afi-safis/afi-safi[afi-safi-name=openconfig-bgp-types:IPV4_UNICAST]/aggregate-addresses',
                    {'aggregate-address': [
                        {'aggregate-address': '8.8.8.0/24',
                         'config': {'aggregate-address': '8.8.8.0/24', 'attribute-map': 'RM-CC-SEAGULL-AGGREGATE'}},
                        {'aggregate-address': '9.9.9.0/24',
                         'config': {'aggregate-address': '9.9.9.0/24', 'attribute-map': 'RM-CC-SEAGULL-A-AGGREGATE'}},
                    ]}
                 ),
            ],
        }

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.replace)
        cu.bgp = messages.BGP(asn="65000", asn_region="65123", switchgroup_id=4223)
        vrf = cu.bgp.get_or_create_vrf("CC-SEAGULL")
        vrf.add_aggregates([
            messages.BGPVRFAggregate(network="8.8.8.0/24", az_local=False),
            messages.BGPVRFAggregate(network="9.9.9.0/24", az_local=True),
        ])

        self.switch.apply_config_update(cu).result()
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
                ('interfaces/interface[name=Port-Channel23]', {
                    'name': 'Port-Channel23',
                    'config': {
                        'name': 'Port-Channel23',
                        'type': 'iana-if-type:ieee8023adLag'
                    },
                    'aggregation': {
                        'config': {
                            'fallback': 'individual',
                            'mlag': 23,
                            'fallback-timeout': 50,
                            'lag-type': 'LACP'
                        },
                        'switched-vlan': {
                            'vlan-translation': {
                                'egress': [{
                                    'config': {
                                        'bridging-vlan': 42,
                                        'translation-key': 23
                                    },
                                    'translation-key': 23
                                }, {
                                    'config': {
                                        'bridging-vlan': 2000,
                                        'translation-key': 1000
                                    },
                                    'translation-key': 1000
                                }],
                                'ingress': [{
                                    'config': {
                                        'bridging-vlan': 23,
                                        'translation-key': 42
                                    },
                                    'translation-key': 42
                                }, {
                                    'config': {
                                        'bridging-vlan': 1000,
                                        'translation-key': 2000
                                    },
                                    'translation-key': 2000
                                }]
                            }
                        }
                    }
                }),
                ('interfaces/interface[name=Ethernet23/1]/ethernet',
                 {'config': {'aggregate-id': 'Port-Channel23'},
                  'switched-vlan': {'vlan-translation': {'egress': [{'config': {'bridging-vlan': 42,
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
                                                                      'translation-key': 2000}]}}})]}

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.add)
        iface = messages.IfaceConfig(name="Port-Channel23", portchannel_id=23, members=["Ethernet23/1"])
        iface.add_vlan_translation(23, 42)
        iface.add_vlan_translation(1000, 2000)
        cu.add_iface(iface)

        self.switch.apply_config_update(cu).result()
        self.switch._api.set.assert_called_with(**expected_config)
        self.switch._api.set.reset_mock()

    def test_replace_vlan_interfaces(self):
        def _get(prefix, unpack=True):
            if prefix == 'interfaces':
                return {
                    'openconfig-interfaces:interface': [
                        {'name': 'Vlan1337', 'config': {'name': 'Vlan1337',
                                                        'type': 'iana-if-type:l3ipvlan'},
                         'arista-exp-eos-varp-intf:arista-varp': {
                         'virtual-address': {'config': {'ip': '1.1.1.1', 'prefix-length': 24}}}},
                        {'name': 'Vlan2001', 'config': {'name': 'Vlan2001',
                                                        'type': 'iana-if-type:l3ipvlan'},
                         'arista-exp-eos-varp-intf:arista-varp': {
                         'virtual-address': {'config': {'ip': '1.1.1.1', 'prefix-length': 24}}}},
                        {'name': 'Vlan2337', 'config': {'name': 'Vlan2337',
                                                        'type': 'iana-if-type:l3ipvlan'},
                         'arista-exp-eos-varp-intf:arista-varp': {
                         'virtual-address': {'config': {'ip': '1.1.1.1', 'prefix-length': 24}}}},
                    ]}
            elif prefix == 'lacp':
                return {'openconfig-lacp:interfaces': {'interface': []}}
            elif not unpack and prefix == 'eos_native:Sysdb/ip/config/ipIntfConfig':
                return {'notification': []}
            raise ValueError(f"unmapped command: {prefix}")
        self.switch._api.get.side_effect = _get
        expected_config = {
            'delete': ['interfaces/interface[name=Vlan2001]'],
            'replace': [],
            'update': [
                ('interfaces/interface[name=Vlan2337]', {
                    'name': 'Vlan2337', 'config': {'name': 'Vlan2337', 'type': 'l3ipvlan'},
                    'arista-varp': {'virtual-address': {'config': {'ip': '1.1.1.1', 'prefix-length': 24}}}})
            ],
        }

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.replace)
        cu.add_vlan_iface(vlan=2337, primary_ip="1.1.1.1/24")

        self.switch.apply_config_update(cu).result()
        self.switch._api.set.assert_called_with(**expected_config)

    def test_replace_bgp_vlans(self):
        def _get(prefix, unpack=True):
            if prefix == 'arista/eos/arista-exp-eos-evpn:evpn/evpn-instances':
                return {
                    'arista-exp-eos-evpn:evpn-instance': [
                        {'config': {'name': '1000',
                                    'route-distinguisher': '4223:10091'},
                         'route-target': {'config': {'export': ['65130:10091'], 'import': ['65130:10091']}},
                         'name': "1000"},
                        {'config': {'name': '2000',
                                    'route-distinguisher': '4223:10091'},
                         'route-target': {'config': {'export': ['65130:10091'], 'import': ['65130:10091']}},
                         'name': "2000"},
                        {'config': {'name': '2004',
                                    'route-distinguisher': 'invalid'},
                         'route-target': {'config': {'export': ['65130:10091'], 'import': ['65130:10091']}},
                         'name': "2004"},
                        {'config': {'name': '2500',
                                    'route-distinguisher': '4223:10091'},
                         'route-target': {'config': {'export': ['65130:10091'], 'import': ['65130:10091']}},
                         'name': "2500"},
                    ]}
            elif not unpack and prefix == 'eos_native:Sysdb/routing/bgp/macvrf/config':
                return {'notification': [
                    {'prefix': 'Sysdb/routing/bgp/macvrf/config/vlan.2004',
                     'update': [
                        {'path': 'remoteRd/valid', 'val': True},
                        {'path': 'remoteRd/rdNboInternal', 'val': 1036957114868695040}]},
                    {'prefix': 'Sysdb/routing/bgp/macvrf/config/vlan.2004/importRemoteDomainRtList',
                     'update': [{'path': '563426694791390', 'val': True}]},
                    {'prefix': 'Sysdb/routing/bgp/macvrf/config/vlan.2004/exportRemoteDomainRtList',
                     'update': [{'path': '564380177531324', 'val': True}]}]}
            raise ValueError(f"unmapped command: {prefix}")
        self.switch._api.get.side_effect = _get

        expected_cli_config = {
            'update': [
                ('cli:', 'router bgp 65000'),
                ('cli:', 'vlan 2004'),
                ('cli:', 'rd evpn domain all 4223:424242'),
                ('cli:', 'no route-target import evpn domain remote 111:222'),
                ('cli:', 'no route-target export evpn domain remote 333:444'),
                ('cli:', 'route-target import evpn domain remote 65123:424242'),
                ('cli:', 'route-target export evpn domain remote 65123:424242'),
                ('cli:', 'exit'),
                ('cli:', 'exit'),
            ],
            'encoding': 'ascii'
        }

        expected_config = {
            'replace':
            [('arista/eos/arista-exp-eos-evpn:evpn/evpn-instances/evpn-instance[name=2000]',
              {
                  'config': {
                      'name': '2000',
                      'route-distinguisher': '4223:232323',
                      'redistribute': ['LEARNED', 'ROUTER_MAC', 'HOST_ROUTE']
                  },
                  'name': '2000',
                  'route-target': {
                      'config': {
                          'export': ['1:232323'],
                          'import': ['1:232323']
                      }
                  },
                  'vlans': {
                      'vlan': [{
                          'config': {
                              'vlan-id': 2000
                          },
                          'vlan-id': 2000
                      }]
                  }
              }),
             ('arista/eos/arista-exp-eos-evpn:evpn/evpn-instances/evpn-instance[name=2004]',
              {
                  'config': {
                      'name': '2004',
                      'route-distinguisher': '4223:424242',
                      'redistribute': ['LEARNED', 'ROUTER_MAC', 'HOST_ROUTE']
                  },
                  'name': '2004',
                  'route-target': {
                      'config': {
                          'export': ['3:424242'],
                          'import': ['3:424242']
                      }
                  },
                  'vlans': {
                      'vlan': [{
                          'config': {
                              'vlan-id': 2004
                          },
                          'vlan-id': 2004
                      }]
                  }
              })],
            'update': [],
            'delete': [
                'arista/eos/arista-exp-eos-evpn:evpn/evpn-instances/evpn-instance[name=2500]',
            ],
        }

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.replace)
        # bgp vlans
        cu.bgp = messages.BGP(asn="65000", asn_region="65123", switchgroup_id=4223)
        cu.bgp.add_vlan(2000, 232323, 1)
        cu.bgp.add_vlan(2004, 424242, 3, bgw_mode=True)

        self.switch.apply_config_update(cu).result()
        self.switch._api.set.assert_has_calls([mock.call(**expected_cli_config), mock.call(**expected_config)])

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
            'update': [('arista/eos/arista-exp-eos-evpn:evpn/evpn-instances/evpn-instance[name=1000]',
                        {'config': {'name': '1000', 'redistribute': ['LEARNED', 'ROUTER_MAC', 'HOST_ROUTE'],
                                    'route-distinguisher': '4223:232323'},
                         'name': '1000',
                         'route-target': {'config': {'export': ['1:232323'],
                                                     'import': ['1:232323']}},
                         'vlans': {'vlan': [{'config': {'vlan-id': 1000},
                                             'vlan-id': 1000}]}})]}

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.add)
        # bgp vlans
        cu.bgp = messages.BGP(asn="65000", asn_region="65123", switchgroup_id=4223)
        cu.bgp.add_vlan(1000, 232323, 1, bgw_mode=True)

        self.switch.apply_config_update(cu).result()
        self.switch._api.set.assert_has_calls([mock.call(**expected_cli_config), mock.call(**expected_config)])


class TestEOSSwitch(base.TestCase):
    def setUp(self):
        super().setUp()
        drv_conf = cfix.make_config(global_config=cfix.make_global_config(asn_region=65130))
        _override_driver_config(drv_conf)
        cfg_switch = config_driver.Switch(name="seagull-sw1", host="127.0.0.1", platform=cc_const.PLATFORM_EOS,
                                          user="seagulladm", password="KRAKRAKRA", bgp_source_ip="1.1.1.1")
        cfg.CONF.set_override('prometheus_enabled', False, group='ml2_cc_fabric_agent')
        with mock.patch.object(n_rpc, 'get_client'):
            self.switch = EOSSwitch(cfg_switch, 65130, 'a', set([100]) | set(range(2000, 3000)), 'cc-eos-switch-agent')
        self.switch._api = mock.Mock()
        self.switch._api.execute.return_value = {'result': [{}]}

    def test_get_switch_config(self):
        def _get(prefix, unpack=True):
            if prefix == 'network-instances/network-instance[name=default]/vlans':
                return {
                    'openconfig-network-instance:vlan': [
                        {'config': {'vlan-id': 2121, 'name': 'b226a569-e0ed-4d24-b943-c7183288'},
                         'vlan-id': 2121},
                        {'config': {'vlan-id': 2122, 'name': 'nest'},
                         'vlan-id': 2122},
                    ]}
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
                         'route-target': {'config': {'export': ['1:10091'], 'import': ['1:10091']}},
                         'name': "2000"},
                        {'config': {'name': '2004',
                                    'route-distinguisher': 'invalid'},
                         'route-target': {'config': {'export': ['3:222222'], 'import': ['3:222222']}},
                         'name': "2004"},
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
                        {'name': 'Port-Channel109', 'config': {'name': 'Port-Channel109',
                                                               'type': 'iana-if-type:ieee8023adLag'},
                         'openconfig-if-aggregate:aggregation': {
                            'openconfig-vlan:switched-vlan': {'config': {
                                'interface-mode': 'TRUNK', 'native-vlan': 2121,
                                'trunk-vlans': ['2000..2002']}}}},
                        {'name': 'Vlan2337', 'config': {'name': 'Vlan2337',
                                                        'type': 'iana-if-type:l3ipvlan'},
                         'arista-exp-eos-varp-intf:arista-varp': {
                         'virtual-address': {'config': {'ip': '1.1.1.1', 'prefix-length': 24}}}},
                        {'name': 'Ethernet1/1', 'config': {'name': 'Ethernet1/1',
                                                           'type': 'iana-if-type:ethernetCsmacd'},
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
            elif not unpack and prefix == 'eos_native:Sysdb/routing/bgp/macvrf/config':
                return {'notification': [
                    {'prefix': 'Sysdb/routing/bgp/macvrf/config/vlan.2004',
                     'update': [
                        {'path': 'remoteRd/valid', 'val': True},
                        {'path': 'remoteRd/rdNboInternal', 'val': 1036957114868695040}]},
                    {'prefix': 'Sysdb/routing/bgp/macvrf/config/vlan.2004/importRemoteDomainRtList',
                     'update': [{'path': '842681173632014', 'val': True}]},
                    {'prefix': 'Sysdb/routing/bgp/macvrf/config/vlan.2004/exportRemoteDomainRtList',
                     'update': [{'path': '842681173632014', 'val': True}]}]}
            elif not unpack and prefix == 'eos_native:Sysdb/ip/config/ipIntfConfig':
                return {'notification': [
                    {'prefix': 'foo'},
                    {'prefix': 'Sysdb/ip/config/ipIntfConfig/Vlan2337/virtualSecondaryWithMask',
                     'update': [{'path': '2.2.2.2/24', 'val': True}, {'path': '3.3.3.3/24', 'val': True}]},
                ]}
            elif prefix == 'routing-policy/defined-sets/prefix-sets':
                return {'openconfig-routing-policy:prefix-set': [
                    {'name': 'PL-CC-TERN', 'config': {'mode': 'IPV4', 'name': 'PL-CC-TERN'},
                     'prefixes': {'prefix': [
                        {'ip-prefix': '10.100.1.0/24', 'masklength-range': 'exact',
                         'config': {'ip-prefix': '10.100.1.0/24', 'masklength-range': 'exact'}},
                        ]}},
                    {'name': 'PL-CC-SEAGULL', 'config': {'mode': 'IPV4', 'name': 'PL-CC-SEAGULL'},
                     'prefixes': {'prefix': [
                         {'ip-prefix': '1.2.3.4/32', 'masklength-range': 'foo',
                          'config': {'ip-prefix': '1.2.3.4/32', 'masklength-range': 'foo'}},
                         {'ip-prefix': '4.4.4.0/24', 'masklength-range': 'exact',
                          'config': {'ip-prefix': '4.4.4.0/24', 'masklength-range': 'exact'}},
                         {'ip-prefix': '5.6.7.8/32', 'masklength-range': 'foo',
                          'config': {'ip-prefix': '5.6.7.8/32', 'masklength-range': 'foo'}},
                     ]}},
                    {'name': 'PL-CC-SEAGULL-EXTERNAL', 'config': {'mode': 'IPV4', 'name': 'PL-CC-SEAGULL-EXTERNAL'},
                     'prefixes': {'prefix': [
                         {'ip-prefix': '5.5.5.0/24', 'masklength-range': 'exact',
                          'config': {'ip-prefix': '5.5.5.0/24', 'masklength-range': 'exact'}},
                     ]}},
                    {'name': 'PL-CC-SEAGULL-A', 'config': {'mode': 'IPV4', 'name': 'PL-CC-SEAGULL-A'},
                     'prefixes': {'prefix': [
                         {'ip-prefix': '6.6.6.0/24', 'masklength-range': 'exact',
                          'config': {'ip-prefix': '6.6.6.0/24', 'masklength-range': 'exact'}},
                     ]}},
                    {'name': 'PL-CC-SEAGULL-A-EXTERNAL', 'config': {'mode': 'IPV4', 'name': 'PL-CC-SEAGULL-A-EXTERNAL'},
                     'prefixes': {'prefix': [
                         {'ip-prefix': '7.7.7.0/24', 'masklength-range': 'exact',
                          'config': {'ip-prefix': '7.7.7.0/24', 'masklength-range': 'exact'}},
                         {'ip-prefix': '10.10.10.0/24', 'masklength-range': 'exact',
                          'config': {'ip-prefix': '10.10.10.0/24', 'masklength-range': 'exact'}},
                     ]}},
                ]}
            elif prefix == 'network-instances':
                return {'openconfig-network-instance:network-instance': [
                    {'config': {'type': 'nesting-ground:seagull'}},
                    {
                        'config': {'type': 'openconfig-network-instance-types:L3VRF'},
                        'name': 'CC-SEAGULL',
                        'interfaces': {'interface': [
                            {'id': 'lolwat', 'config': {'id': 'lolwat', 'interface': 'lolwat'}},
                            {'id': 'Vlan1337', 'config': {'id': 'Vlan1337', 'interface': 'Vlan1337'}},
                            {'id': 'Vlan2337', 'config': {'id': 'Vlan2337', 'interface': 'Vlan2337'}},
                        ]},
                        'protocols': {'protocol': [
                            {'name': 'TERN-TERN-TERN', 'config': {'name': 'TERN-TERN-TERN'}},
                            {
                                'config': {'identifier': 'openconfig-policy-types:BGP', 'name': 'BGP'},
                                'name': 'BGP',
                                'bgp': {'global': {'afi-safis': {'afi-safi': [
                                    {'afi-safi-name': 'openconfig-bgp-types:IPV4_UNICAST',
                                     'config': {'afi-safi-name': 'openconfig-bgp-types:IPV4_UNICAST', 'enabled': True}},
                                    {'afi-safi-name': 'openconfig-bgp-types:IPV4_UNICAST',
                                     'config': {'afi-safi-name': 'openconfig-bgp-types:IPV4_UNICAST', 'enabled': True},
                                     'arista-bgp-augments:aggregate-addresses': {'aggregate-address': [
                                         {'aggregate-address': '12.12.12.0/24', 'config': {
                                             'aggregate-address': '12.12.12.0/24', 'attribute-map': 'TERN-TERN-TERN'}},
                                         {'aggregate-address': '8.8.8.0/24', 'config': {
                                             'aggregate-address': '8.8.8.0/24',
                                             'attribute-map': 'RM-CC-SEAGULL-AGGREGATE'}},
                                         {'aggregate-address': '9.9.9.0/24', 'config': {
                                             'aggregate-address': '9.9.9.0/24',
                                             'attribute-map': 'RM-CC-SEAGULL-A-AGGREGATE'}},
                                     ]}},
                                ]}}}
                            },
                        ],
                        }},
                ]}

            raise ValueError(f"unmapped command: {prefix}")
        self.switch._api.get.side_effect = _get

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.add)
        cu.add_vlan(2121, "b226a569-e0ed-4d24-b943-c7183288")
        cu.add_vlan(2122, "nest")
        cu.add_vxlan_map(31337, 2121)
        cu.bgp = messages.BGP(asn="65130.4113", asn_region=65130, switchgroup_id=4223)
        cu.bgp.add_vlan(2000, 10091, 1, bgw_mode=False)
        cu.bgp.add_vlan(2004, 222222, 3, bgw_mode=True)
        cu.bgp.switchgroup_id = None  # not needed for comparison (not fetched from switch)
        iface = messages.IfaceConfig(name="Port-Channel109", members=["Ethernet9/1"],
                                     trunk_vlans=[2000, 2001, 2002], native_vlan=2121, portchannel_id=109)
        cu.add_iface(iface)
        iface = messages.IfaceConfig(name="Ethernet1/1")
        iface.add_vlan_translation(2000, 3001)
        cu.add_iface(iface)

        cu.add_vlan_iface(vlan=2337, vrf="CC-SEAGULL", primary_ip="1.1.1.1/24",
                          secondary_ips=["2.2.2.2/24", "3.3.3.3/24"])
        vrf = cu.bgp.get_or_create_vrf("CC-SEAGULL")
        vrf.add_networks([
            messages.BGPVRFNetwork(network="4.4.4.0/24", az_local=False, ext_announcable=False),
            messages.BGPVRFNetwork(network="5.5.5.0/24", az_local=False, ext_announcable=True),
            messages.BGPVRFNetwork(network="6.6.6.0/24", az_local=True, ext_announcable=False),
            messages.BGPVRFNetwork(network="7.7.7.0/24", az_local=True, ext_announcable=True),
            messages.BGPVRFNetwork(network="10.10.10.0/24", az_local=True, ext_announcable=True),
        ])
        vrf.add_aggregates([
            messages.BGPVRFAggregate(network="8.8.8.0/24", az_local=False),
            messages.BGPVRFAggregate(network="9.9.9.0/24", az_local=True),
        ])

        cu.sort()

        config = self.switch.get_config().result()
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
