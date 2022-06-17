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

import re
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
        self.switch._api.execute.return_value = {'result': [{}]}

    def test_add_vlans(self):
        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.add)
        cu.add_vlan(1000, "nest")
        cu.add_vlan(1001, "basket")
        self.switch.apply_config_update(cu)
        self.switch._api.execute.assert_called_with(
            ['configure', 'vlan 1000', 'name nest', 'exit', 'vlan 1001', 'name basket', 'exit', 'end'], format='json')

    def test_add_everything(self):
        def execute(cmd, format='json'):
            if cmd == "show interfaces Vxlan1":
                return {"result": [{"interfaces": {"Vxlan1": {"vlanToVniMap": {"2121": {"vni": 31337}}}}}]}
            return {"result": None}
        self.switch._api.execute.side_effect = execute

        expected_config = [
            'configure',
            'vlan 1000',
            'name nest',
            'exit',
            'vlan 1001',
            'name basket',
            'exit',
            'interface Vxlan1',
            'vxlan vlan add 1000 vni 232323',
            'vxlan vlan add 1001 vni 424242',
            'exit',
            'router bgp 65000',
            'vlan 1000',
            'rd 65000:232323',
            'route-target import 65123:232323',
            'route-target export 65123:232323',
            'redistribute learned',
            'exit',
            'exit',
            'interface Port-channel23',
            'mlag 23',
            'switchport mode trunk',
            'switchport trunk native vlan 1000',
            'switchport trunk allowed vlan add 1000,1001',
            'switchport vlan translation 2323 1000',
            'switchport vlan translation 1337 1001',
            'exit',
            'interface Ethernet4/1',
            'channel-group 23 mode active',
            'switchport mode trunk',
            'switchport trunk native vlan 1000',
            'switchport trunk allowed vlan add 1000,1001',
            'switchport vlan translation 2323 1000',
            'switchport vlan translation 1337 1001',
            'exit',
            'interface Ethernet4/2',
            'channel-group 23 mode active',
            'switchport mode trunk',
            'switchport trunk native vlan 1000',
            'switchport trunk allowed vlan add 1000,1001',
            'switchport vlan translation 2323 1000',
            'switchport vlan translation 1337 1001',
            'exit',
            'interface Ethernet23/1',
            'switchport mode trunk',
            'switchport trunk allowed vlan add 1001',
            'exit',
            'end']

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.add)
        # vlans
        cu.add_vlan(1000, "nest")
        cu.add_vlan(1001, "basket")

        # vxlan maps
        cu.add_vxlan_map(232323, 1000)
        cu.add_vxlan_map(424242, 1001)

        # bgp stuff / vlans
        cu.bgp = messages.BGP(asn="65000", asn_region="65123")
        cu.bgp.add_vlan(1000, 232323)

        # interfaces
        iface1 = messages.IfaceConfig(name="Port-channel23", portchannel_id=23, native_vlan=1000,
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
        self.switch._api.execute.assert_called_with(expected_config, format='json')

    def test_remove_everything(self):
        expected_config = [
            'configure',
            'no vlan 1000',
            'no vlan 1001',
            'interface Vxlan1',
            'no vxlan vlan 1000 vni 232323',
            'no vxlan vlan 1001 vni 424242',
            'exit',
            'router bgp 65000',
            'no vlan 1000',
            'exit',
            'interface Port-channel23',
            'switchport mode trunk',
            'no switchport trunk native vlan',
            'switchport trunk allowed vlan remove 1000,1001',
            'no switchport vlan translation 2323 1000',
            'no switchport vlan translation 1337 1001',
            'exit',
            'interface Ethernet4/1',
            'switchport mode trunk',
            'no switchport trunk native vlan',
            'switchport trunk allowed vlan remove 1000,1001',
            'no switchport vlan translation 2323 1000',
            'no switchport vlan translation 1337 1001',
            'exit',
            'interface Ethernet4/2',
            'switchport mode trunk',
            'no switchport trunk native vlan',
            'switchport trunk allowed vlan remove 1000,1001',
            'no switchport vlan translation 2323 1000',
            'no switchport vlan translation 1337 1001',
            'exit',
            'interface Ethernet23/1',
            'switchport mode trunk',
            'switchport trunk allowed vlan remove 1001',
            'exit',
            'end']

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.remove)
        # vlans
        cu.add_vlan(1000, "nest")
        cu.add_vlan(1001, "basket")

        # vxlan maps
        cu.add_vxlan_map(232323, 1000)
        cu.add_vxlan_map(424242, 1001)

        # bgp stuff / vlans
        cu.bgp = messages.BGP(asn="65000", asn_region="65123")
        cu.bgp.add_vlan(1000, 232323)

        # interfaces
        iface1 = messages.IfaceConfig(name="Port-channel23", portchannel_id=23, native_vlan=1000,
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
        self.switch._api.execute.assert_called_with(expected_config, format='json')

    def test_add_vlan_map_with_existing(self):
        def execute(cmd, format='json'):
            if cmd == "show interfaces Vxlan1":
                return {"result": [
                    {"interfaces":
                        {"Vxlan1":
                            {"vlanToVniMap": {"2000": {"vni": 31337}, "2500": {"vni": 232323}, "2": {"vni": 3}}}}}]}
            return {"result": None}
        self.switch._api.execute.side_effect = execute

        expected_config = [
            'configure',
            'interface Vxlan1',
            'no vxlan vlan 2000 vni 31337',
            'no vxlan vlan 2500 vni 232323',
            'vxlan vlan add 1000 vni 232323',
            'vxlan vlan add 2000 vni 424242',
            'exit',
            'end']

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.add)
        cu.add_vxlan_map(232323, 1000)
        cu.add_vxlan_map(424242, 2000)

        self.switch.apply_config_update(cu)
        self.switch._api.execute.assert_called_with(expected_config, format='json')

    def test_replace_trunk_vlans(self):
        expected_config = [
            'configure',
            'interface Ethernet23/1',
            'switchport mode trunk',
            'switchport trunk allowed vlan 1001',
            'exit',
            'end'
        ]

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.replace)
        iface = messages.IfaceConfig(name="Ethernet23/1")
        iface.add_trunk_vlan(1001)
        cu.add_iface(iface)

        self.switch.apply_config_update(cu)
        self.switch._api.execute.assert_called_with(expected_config, format='json')

    def test_replace_vlans(self):
        def execute(cmd, format='json'):
            if cmd == "show vlan":
                return {'result': [
                    {'vlans': {str(v): {} for v in [1, 100, 1000, 1003, 4093, 4094]}},
                ]}
            return mock.DEFAULT
        self.switch._api.execute.side_effect = execute

        expected_config = [
            'configure',
            'no vlan 100',
            'no vlan 1003',
            'vlan 1000',
            'name nest',
            'exit',
            'vlan 1001',
            'name basket',
            'exit',
            'end'
        ]

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.replace)
        # vlans
        cu.add_vlan(1000, "nest")
        cu.add_vlan(1001, "basket")

        self.switch.apply_config_update(cu)
        self.switch._api.execute.assert_called_with(expected_config, format='json')

    def test_replace_vxlan_maps(self):
        def execute(cmd, format='json'):
            if cmd == "show interfaces Vxlan1":
                return {'result': [
                    {'interfaces': {'Vxlan1': {
                        'vlanToVniMap': {vlan: {'vni': vni} for vni, vlan in
                                         [(23, 42), (2000, 444), (424242, 2000)]}
                    }}}]}
            return mock.DEFAULT
        self.switch._api.execute.side_effect = execute

        expected_config = [
            'configure',
            'interface Vxlan1',
            'no vxlan vlan 444 vni 2000',
            'no vxlan vlan 2000 vni 424242',
            'vxlan vlan add 42 vni 23',
            'vxlan vlan add 1337 vni 232323',
            'exit',
            'end'
        ]

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.replace)
        # vlans
        cu.add_vxlan_map(23, 42)
        cu.add_vxlan_map(232323, 1337)

        self.switch.apply_config_update(cu)
        self.switch._api.execute.assert_called_with(expected_config, format='json')

    def test_replace_vlan_translations(self):
        def execute(cmd, format='json'):
            if isinstance(cmd, str):
                m = re.match("show interfaces (?P<iface>[^ ]+) switchport vlan mapping", cmd)
                if m:
                    iface = m.group('iface')
                    if iface == 'Eth23/1':
                        iface = 'Ethernet23/1'
                    avail_trans = {
                        'Ethernet23/1': [(23, 42), (2000, 3000)],
                        'Port-channel23': [(23, 42), (3000, 4000)],
                    }
                    maps = {outside: {'vlanId': inside} for inside, outside in avail_trans[iface]}

                    return {'result': [
                        {'intfVlanMappings': {iface: {'ingressVlanMappings': maps, 'egressVlanMappings': maps}}}]}
            return mock.DEFAULT
        self.switch._api.execute.side_effect = execute

        # single interface
        expected_config = [
            'configure',
            'interface Eth23/1',
            'no switchport vlan translation 3000 2000',
            'switchport mode trunk',
            'switchport vlan translation 42 23',
            'switchport vlan translation 2000 1000',
            'exit',
            'end'
        ]
        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.replace)
        iface = messages.IfaceConfig(name="Eth23/1")  # deliberate use of shorthand for interface name
        iface.add_vlan_translation(23, 42)
        iface.add_vlan_translation(1000, 2000)
        cu.add_iface(iface)

        self.switch.apply_config_update(cu)
        self.switch._api.execute.assert_called_with(expected_config, format='json')
        self.switch._api.execute.reset_mock()

        # port-channel with one member interface
        expected_config = [
            'configure',
            'interface Port-channel23',
            'mlag 23',
            'no switchport vlan translation 4000 3000',
            'switchport mode trunk',
            'switchport vlan translation 42 23',
            'switchport vlan translation 2000 1000',
            'exit',
            'interface Ethernet23/1',
            'channel-group 23 mode active',
            'no switchport vlan translation 3000 2000',
            'switchport mode trunk',
            'switchport vlan translation 42 23',
            'switchport vlan translation 2000 1000',
            'exit',
            'end'
        ]

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.replace)
        iface = messages.IfaceConfig(name="Port-channel23", portchannel_id=23,
                                     members=["Ethernet23/1"])
        iface.add_vlan_translation(23, 42)
        iface.add_vlan_translation(1000, 2000)
        cu.add_iface(iface)

        self.switch.apply_config_update(cu)
        self.switch._api.execute.assert_called_with(expected_config, format='json')

    def test_replace_bgp_vlans(self):
        def execute(cmd, format='json'):
            if cmd == "show bgp evpn instance":
                return {'result': [{'bgpEvpnInstances': {
                                    'VLAN 2323': {'rd': '1.1.11.0:44444', 'encapType': 'vxlan'}}}]}
            return mock.DEFAULT
        self.switch._api.execute.side_effect = execute

        expected_config = [
            'configure',
            'router bgp 65000',
            'no vlan 2323',
            'vlan 1000',
            'rd 65000:232323',
            'route-target import 65123:232323',
            'route-target export 65123:232323',
            'redistribute learned',
            'exit',
            'exit',
            'end'
        ]

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.replace)
        # bgp vlans
        cu.bgp = messages.BGP(asn="65000", asn_region="65123")
        cu.bgp.add_vlan(1000, 232323)

        self.switch.apply_config_update(cu)
        self.switch._api.execute.assert_called_with(expected_config, format='json')

    def test_bgp_vlans_bgw_mode(self):
        expected_config = [
            'configure',
            'router bgp 65000',
            'vlan 1000',
            'rd evpn domain all 65000:232323',
            'route-target import 65123:232323',
            'route-target export 65123:232323',
            'route-target import evpn domain remote 65123:232323',
            'route-target export evpn domain remote 65123:232323',
            'redistribute learned',
            'exit',
            'exit',
            'end'
        ]

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.add)
        # bgp vlans
        cu.bgp = messages.BGP(asn="65000", asn_region="65123")
        cu.bgp.add_vlan(1000, 232323, bgw_mode=True)

        self.switch.apply_config_update(cu)
        self.switch._api.execute.assert_called_with(expected_config, format='json')


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
        def execute(cmd, format='json'):
            cmds = {
                'show vlan': {
                    "vlans": {
                        "2121": {
                            "status": "active",
                            "name": "b226a569-e0ed-4d24-b943-c7183288",
                        },
                    },
                },
                'show interfaces Vxlan1': {
                    "interfaces": {
                        "Vxlan1": {
                            "vlanToVniMap": {
                                "2121": {
                                    "vni": 31337,
                                },
                            },
                        },
                    },
                },
                'show bgp summary': {
                    "vrfs": {
                        "default": {
                            "asn": "65130.4113",
                        },
                    },
                },
                'show bgp evpn instance': {
                    "bgpEvpnInstances": {
                        "VLAN 2000": {
                            "rd": "4268363793:10091",
                            "importRts": [
                                842681173419883,
                            ],
                            "exportRts": [
                                842681173419883,
                            ],
                        },
                    },
                },
                'show interfaces vlans': {
                    "interfaces": {
                        "Port-Channel109": {
                            "taggedVlans": [
                                2000,
                                2001,
                                2002,
                            ],
                            "untaggedVlan": 2121,
                        },
                    },
                },
                'show interfaces switchport vlan mapping': {
                    "intfVlanMappings": {
                        "Ethernet1/1": {
                            "ingressVlanMappings": {
                                "3001": {
                                    "vlanId": 2000
                                },
                            },
                            "egressVlanMappings": {
                                "2000": {
                                    "vlanId": 3001
                                },
                            },
                        },
                    },
                },
                'show port-channel dense': {
                    "portChannels": {
                        "Port-Channel109": {
                            "protocol": "lacp",
                            "fallback": {
                                "config": "fallbackIndividual"
                            },
                            "lacpMode": "active",
                            "linkState": "up",
                            "ports": {
                                "PeerEthernet9/1": {},
                                "Ethernet9/1": {},
                            },
                        },
                    },
                },
            }
            if cmd in cmds:
                return dict(result=[cmds[cmd]])
            else:
                return ValueError("unmapped command")
        self.switch._api.execute.side_effect = execute

        cu = messages.SwitchConfigUpdate(switch_name="seagull-sw1", operation=messages.OperationEnum.add)
        cu.add_vlan(2121, "b226a569-e0ed-4d24-b943-c7183288")
        cu.add_vxlan_map(31337, 2121)
        cu.bgp = messages.BGP(asn=65130.4113, asn_region=65130)
        cu.bgp.add_vlan(2000, 10091, bgw_mode=False)
        iface = messages.IfaceConfig(name="Port-Channel109", members=["Ethernet9/1"],
                                     trunk_vlans=[2000, 2001, 2002], native_vlan=2121, portchannel_id=109)
        cu.add_iface(iface)
        iface = messages.IfaceConfig(name="Ethernet1/1")
        iface.add_vlan_translation(2000, 3001)
        cu.add_iface(iface)

        config = self.switch.get_config()
        self.assertEqual(cu.dict(exclude_unset=True, exclude_defaults=True),
                         config.dict(exclude_unset=True, exclude_defaults=True))
