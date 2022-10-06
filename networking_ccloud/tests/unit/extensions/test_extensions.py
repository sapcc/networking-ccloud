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

from neutron.api import extensions
from neutron.db.models import segment as segment_models
from neutron.tests.unit.api.test_extensions import setup_extensions_middleware
from neutron.tests.unit.extensions import test_segment
from neutron_lib import context
from neutron_lib.plugins.ml2 import api as ml2_api
import webtest

from networking_ccloud.common.config import _override_driver_config
from networking_ccloud.common.config.config_driver import InfraNetwork
from networking_ccloud.common import constants as cc_const
from networking_ccloud.db.db_plugin import CCDbPlugin
from networking_ccloud.extensions import __path__ as fabric_ext_path
from networking_ccloud.extensions import fabricoperations
from networking_ccloud.ml2.agent.common.api import CCFabricSwitchAgentRPCClient
from networking_ccloud.tests import base
from networking_ccloud.tests.common import config_fixtures as cfix


class TestCustomExtension(base.TestCase):
    def setUp(self):
        super().setUp()
        _override_driver_config(123)  # FIXME proper fake config
        self.ext_mgr = extensions.ExtensionManager(fabric_ext_path[0])
        self.app = webtest.TestApp(setup_extensions_middleware(self.ext_mgr))

    def test_extension_registration(self):
        fabricoperations.register_api_extension()
        ext_paths = extensions.get_extensions_path()
        self.assertIn(fabric_ext_path[0], ext_paths)

    def test_extension_loaded(self):
        assert fabricoperations.Fabricoperations.get_alias() in self.ext_mgr.extensions

    def test_extension_status(self):
        resp = self.app.get("/cc-fabric/status")
        self.assertEqual({'driver_reached': True}, resp.json)


class TestSyncExtension(base.TestCase):
    def setUp(self):
        super().setUp()

        _override_driver_config(123)  # FIXME proper fake config
        self.ext_mgr = extensions.ExtensionManager(fabric_ext_path[0])
        self.app = webtest.TestApp(setup_extensions_middleware(self.ext_mgr))

    def test_extension_status(self):
        resp = self.app.get("/cc-fabric/status")
        self.assertEqual({'driver_reached': True}, resp.json)


class TestNetworkExtension(test_segment.SegmentTestCase, base.PortBindingHelper):
    def setUp(self):
        super().setUp()

        # make config
        switchgroups = [
            cfix.make_switchgroup("seagull", availability_zone="qa-de-1a"),
            cfix.make_switchgroup("transit1", availability_zone="qa-de-1a"),
            cfix.make_switchgroup("bgw1", availability_zone="qa-de-1a"),

            cfix.make_switchgroup("crow", availability_zone="qa-de-1b"),
            cfix.make_switchgroup("transit2", availability_zone="qa-de-1b"),
            cfix.make_switchgroup("bgw2", availability_zone="qa-de-1b"),

            cfix.make_switchgroup("sentinel", availability_zone="qa-de-1a",
                                  switch_vars=dict(platform=cc_const.PLATFORM_EOS)),
        ]
        seagull_infra_nets = [
            InfraNetwork(name="infra_net_l3", vlan=23, networks=["10.23.42.1/24"], vrf='PRIVATE-VRF', vni=6667),
            InfraNetwork(name="infra_net_vlan", vlan=42, vni=14),
        ]
        hg_seagull = cfix.make_metagroup("seagull", meta_kwargs={'infra_networks': seagull_infra_nets})
        hg_crow = cfix.make_metagroup("crow", meta_kwargs={'extra_vlans': [13, 37]})
        interconnects = [
            cfix.make_interconnect(cc_const.DEVICE_TYPE_TRANSIT, "transit1", "transit1", ["qa-de-1a"]),
            cfix.make_interconnect(cc_const.DEVICE_TYPE_TRANSIT, "transit2", "transit2", ["qa-de-1b"]),
            cfix.make_interconnect(cc_const.DEVICE_TYPE_BGW, "bgw1", "bgw1", ["qa-de-1a"]),
            cfix.make_interconnect(cc_const.DEVICE_TYPE_BGW, "bgw2", "bgw2", ["qa-de-1b"]),
        ]
        hostgroups = hg_seagull + hg_crow + interconnects

        self.conf_drv = cfix.make_config(switchgroups=switchgroups, hostgroups=hostgroups)
        _override_driver_config(self.conf_drv)
        self.db = CCDbPlugin()
        self.ctx = context.get_admin_context()

        self._net_a = self._make_network(name="a", admin_state_up=True, fmt='json')['network']
        for az in ('a', 'b'):
            self.db.ensure_bgw_for_network(self.ctx, self._net_a['id'], f"qa-de-1{az}")
            self.db.ensure_transit_for_network(self.ctx, self._net_a['id'], f"qa-de-1{az}")

        self._seg_a = {physnet: self._make_segment(network_id=self._net_a['id'], network_type='vlan',
                       physical_network=physnet, segmentation_id=seg_id, tenant_id='test-tenant',
                       fmt='json')['segment']
                       for physnet, seg_id in (('seagull', 100), ('crow', 200), ('bgw1', 234), ('bgw2', 345),
                                               ('transit1', 111), ('transit2', 222))}
        self._seg_a[None] = self._make_segment(network_id=self._net_a['id'], network_type='vxlan',
                                               segmentation_id=232323,
                                               tenant_id="test-tenant", fmt='json')['segment']
        self._port_a_1 = self._make_port_with_binding(segments=[(self._seg_a[None], 'cc-fabric'),
                                                                (self._seg_a['seagull'], 'meow-ml2')],
                                                      host='nova-compute-seagull')
        self._port_a_2 = self._make_port_with_binding(segments=[(self._seg_a[None], 'cc-fabric'),
                                                                (self._seg_a['crow'], 'meow-ml2')],
                                                      host='nova-compute-crow')

        # fix segment index
        with self.ctx.session.begin():
            objs = self.ctx.session.query(segment_models.NetworkSegment).filter_by(physical_network=None,
                                                                                   network_type='vxlan')
            objs.update({'segment_index': 0})

        self.ext_mgr = extensions.ExtensionManager(fabric_ext_path[0])
        self.app = webtest.TestApp(setup_extensions_middleware(self.ext_mgr))

    def test_network_get(self):
        resp = self.app.get(f"/cc-fabric/networks/{self._net_a['id']}")
        net = resp.json
        self.assertEqual({'nova-compute-seagull', 'nova-compute-crow'}, set(net['hosts']))
        self.assertEqual(4, len(net['interconnects']))
        self.assertEqual({'bgw', 'transit'}, {ic['device_type'] for ic in net['interconnects']})

    def test_network_ensure_interconnects(self):
        with self.network() as network:
            network_id = network['network']['id']
            self._make_segment(network_id=network_id, network_type='vxlan',
                               segmentation_id=424242,
                               tenant_id="test-tenant", fmt='json')['segment']

            # make sure nothing is allocated
            self.assertEqual([], self.db.get_interconnects(self.ctx, network_id))

            # make apicall
            fake_new_segment = {'id': 'my-uuid', ml2_api.SEGMENTATION_ID: 1234}
            with mock.patch.object(test_segment.SegmentTestPlugin, 'type_manager', create=True) as mock_tm, \
                    mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
                mock_tm.allocate_dynamic_segment.return_value = fake_new_segment
                self.app.put(f"/cc-fabric/networks/{network_id}/ensure_interconnects")
                mock_tm.allocate_dynamic_segment.assert_called()
                mock_acu.assert_called()

            # make sure interconnects are now present
            self.assertEqual(4, len(self.db.get_interconnects(self.ctx, network_id)))

    def test_network_sync(self):
        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
            resp = self.app.put(f"/cc-fabric/networks/{self._net_a['id']}/sync")
            self.assertTrue(resp.json['sync_sent'])
            mock_acu.assert_called()
            swcfg = mock_acu.call_args[0][1]
            self.assertEqual({"seagull-sw1", "seagull-sw2", "crow-sw1", "crow-sw2",
                              "transit1-sw1", "transit2-sw1", "bgw1-sw1", "bgw2-sw1"},
                             set(s.switch_name for s in swcfg))

            # FIXME: check that all necessary switches are synced

    def test_switches(self):
        # index
        resp = self.app.get("/cc-fabric/switches")
        switches = resp.json
        self.assertEqual(14, len(switches))
        self.assertEqual("seagull-sw1", switches[0]['name'])

        # detail
        resp = self.app.get("/cc-fabric/switches/seagull-sw1")
        switch = resp.json
        self.assertEqual("seagull-sw1", switch['name'])

    def test_switches_with_info(self):
        def fake_get_switch_status(context, switches):
            switch_info = {switch: {'reachable': True, 'uptime': '23 s', 'version': 'Windows 95'}
                           for switch in switches[:-1]}
            switch_info[switches[-1]] = {'reachable': False, 'error': '...unreachable?'}
            return {'switches': switch_info}

        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'get_switch_status',
                               side_effect=fake_get_switch_status) as mock_gss:
            # index
            resp = self.app.get("/cc-fabric/switches?device_info=1")
            switches = resp.json
            self.assertEqual(14, len(switches))
            self.assertEqual("seagull-sw1", switches[0]['name'])
            self.assertTrue(all(s['device_info']['found'] for s in switches))
            self.assertEqual(2, mock_gss.call_count)
            self.assertEqual('...unreachable?', switches[-1]['device_error'])
            mock_gss.reset_mock()

            # detail
            resp = self.app.get("/cc-fabric/switches/seagull-sw1?device_info=1")
            switch = resp.json
            self.assertEqual("seagull-sw1", switch['name'])
            self.assertTrue(switch['device_info']['found'])
            mock_gss.assert_called_once()

    def test_switch_sync_vpod(self):
        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
            resp = self.app.put("/cc-fabric/switches/seagull-sw1/sync")
            self.assertTrue(resp.json['sync_sent'])
            mock_acu.assert_called()
            swcfgs = mock_acu.call_args[0][1]

            # assert only this one switch was synced and nothing else
            self.assertEqual({"seagull-sw1"}, set(s.switch_name for s in swcfgs))

            # check that infra networks and portbindings are synced
            for swcfg in swcfgs:
                for iface in swcfg.ifaces:
                    self.assertEqual({23, 42, 100}, set(iface.trunk_vlans))

    def test_switch_sync_vpod_extra_vlans(self):
        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
            resp = self.app.put("/cc-fabric/switches/crow-sw1/sync")
            self.assertTrue(resp.json['sync_sent'])
            mock_acu.assert_called()
            swcfgs = mock_acu.call_args[0][1]

            self.assertEqual({"crow-sw1"}, set(s.switch_name for s in swcfgs))

            for swcfg in swcfgs:
                for iface in swcfg.ifaces:
                    self.assertEqual({13, 37, 200}, set(iface.trunk_vlans))

    def test_switch_sync_vpod_infra_networks(self):
        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
            resp = self.app.put("/cc-fabric/switches/seagull-sw1/sync_infra_networks")
            self.assertTrue(resp.json['sync_sent'])
            mock_acu.assert_called()
            swcfgs = mock_acu.call_args[0][1]
            self.assertEqual({"seagull-sw1"}, set(s.switch_name for s in swcfgs))
            for swcfg in swcfgs:
                for iface in swcfg.ifaces:
                    self.assertEqual({23, 42}, set(iface.trunk_vlans))

    def test_switch_sync_vpod_infra_networks_with_extra_vlans(self):
        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
            resp = self.app.put("/cc-fabric/switches/crow-sw1/sync_infra_networks")
            self.assertTrue(resp.json['sync_sent'])
            mock_acu.assert_called()
            swcfgs = mock_acu.call_args[0][1]
            self.assertEqual({"crow-sw1"}, set(s.switch_name for s in swcfgs))
            for swcfg in swcfgs:
                for iface in swcfg.ifaces:
                    self.assertEqual({13, 37}, set(iface.trunk_vlans))

    def test_switch_sync_interconnect_bgw(self):
        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
            resp = self.app.put("/cc-fabric/switches/bgw1-sw1/sync")
            self.assertTrue(resp.json['sync_sent'])
            mock_acu.assert_called()
            swcfgs = mock_acu.call_args[0][1]
            self.assertEqual({"bgw1-sw1"}, set(s.switch_name for s in swcfgs))
            for swcfg in swcfgs:
                self.assertIsNone(swcfg.ifaces)
                self.assertEqual({234}, {v.vlan for v in swcfg.vlans})

    def test_switch_sync_interconnect_bgw_infranetworks_empty(self):
        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
            # bgw1 has no infra networks --> should be a noop
            resp = self.app.put("/cc-fabric/switches/bgw1-sw1/sync_infra_networks")
            self.assertFalse(resp.json['sync_sent'])
            mock_acu.assert_not_called()

    def test_switch_sync_interconnect_transit(self):
        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
            resp = self.app.put("/cc-fabric/switches/transit1-sw1/sync")
            self.assertTrue(resp.json['sync_sent'])
            mock_acu.assert_called()
            swcfgs = mock_acu.call_args[0][1]
            self.assertEqual({"transit1-sw1"}, set(s.switch_name for s in swcfgs))
            for swcfg in swcfgs:
                self.assertEqual([{'vni': 232323, 'vlan': 111}], swcfg.vxlan_maps)
                self.assertIsNone(swcfg.ifaces)

    def test_switch_get_config(self):
        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'get_switch_config') as mock_gsc:
            mock_gsc.return_value = {
                'switches': {
                    'seagull-sw1': {'reachable': True, 'config': {'operation': 'add', 'switch_name': 'seagull-sw1'}},
                },
            }
            resp = self.app.get("/cc-fabric/switches/seagull-sw1/config")
            expected = {
                'reachable': True,
                'config': {
                    'switch_name': 'seagull-sw1',
                },
            }
            self.assertEqual(expected, resp.json)

    def test_switch_get_os_config(self):
        resp = self.app.get("/cc-fabric/switches/seagull-sw1/os_config")
        # just make sure it looks somewhat relatable to what we expect / have set in the db
        self.assertEqual(10, len(resp.json['config']['ifaces']))
        self.assertEqual([23, 42, 100], resp.json['config']['ifaces'][0]['trunk_vlans'])

    def test_switchgroups(self):
        # index
        resp = self.app.get("/cc-fabric/switchgroups")
        sgs = resp.json
        self.assertEqual(7, len(sgs))
        self.assertEqual("seagull", sgs[0]['name'])

        # detail
        resp = self.app.get("/cc-fabric/switchgroups/seagull")
        sg = resp.json
        self.assertEqual("seagull", sg['name'])
        self.assertEqual({"seagull-sw1", "seagull-sw2"}, {s['name'] for s in sg['members']})

    def test_switchgroups_with_info(self):
        def fake_get_switch_status(context, switches):
            switch_info = {switch: {'reachable': True, 'uptime': '23 s', 'version': 'Windows 95'}
                           for switch in switches}
            return {'switches': switch_info}

        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'get_switch_status',
                               side_effect=fake_get_switch_status) as mock_gss:

            # index
            resp = self.app.get("/cc-fabric/switchgroups?device_info=1")
            sgs = resp.json
            self.assertEqual(7, len(sgs))
            self.assertTrue("seagull", sgs[0]['members'][0]['device_info']['reachable'])
            self.assertEqual(14, mock_gss.call_count)
            mock_gss.reset_mock()

            # detail
            resp = self.app.get("/cc-fabric/switchgroups/seagull?device_info=1")
            sg = resp.json
            self.assertEqual("seagull", sg['name'])
            self.assertTrue(sg['members'][0]['device_info']['reachable'])
            self.assertEqual(2, mock_gss.call_count)

    def test_switchgroup_sync(self):
        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
            resp = self.app.put("/cc-fabric/switchgroups/seagull/sync")
            self.assertEqual(1, mock_acu.call_count)
            self.assertTrue(resp.json['sync_sent'])
            swcfgs = mock_acu.call_args[0][1]

            self.assertEqual({"seagull-sw1", "seagull-sw2"}, set(s.switch_name for s in swcfgs))

            # check that infra networks and portbindings are synced
            for swcfg in swcfgs:
                for iface in swcfg.ifaces:
                    self.assertEqual({23, 42, 100}, set(iface.trunk_vlans))

    def test_switchgroup_sync_infra_networks(self):
        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
            resp = self.app.put("/cc-fabric/switchgroups/seagull/sync_infra_networks")
            self.assertEqual(2, mock_acu.call_count)
            expected = {
                'seagull-sw1': {'sync_sent': True},
                'seagull-sw2': {'sync_sent': True},
            }
            self.assertEqual(expected, resp.json)

    def test_switchgroup_get_config(self):
        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'get_switch_config') as mock_gsc:
            mock_gsc.return_value = {
                'switches': {
                    'seagull-sw1': {'reachable': True, 'config': {'operation': 'add', 'switch_name': 'seagull-sw1'}},
                    'seagull-sw2': {'reachable': True, 'config': {'operation': 'add', 'switch_name': 'seagull-sw2'}},
                },
            }
            resp = self.app.get("/cc-fabric/switchgroups/seagull/config")
            expected = {
                'seagull-sw1': {
                    'reachable': True,
                    'config': {
                        'switch_name': 'seagull-sw1',
                    },
                },
                'seagull-sw2': {
                    'reachable': True,
                    'config': {
                        'switch_name': 'seagull-sw2',
                    },
                },
            }
            self.assertEqual(expected, resp.json)

    def test_switchgroup_get_os_config(self):
        resp = self.app.get("/cc-fabric/switchgroups/seagull/os_config")
        for switch in 'seagull-sw1', 'seagull-sw2':
            cfg = resp.json[switch]
            # just make sure it looks somewhat relatable to what we expect / have set in the db
            self.assertEqual(10, len(cfg['config']['ifaces']))
            self.assertEqual([23, 42, 100], cfg['config']['ifaces'][0]['trunk_vlans'])

    def test_create_all_portchannels(self):
        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
            resp = self.app.put("/cc-fabric/switches/create_all_portchannels")
            self.assertTrue(resp.json['sync_sent'])
            swcfgs = mock_acu.call_args[0][1]
            self.assertEqual(1, mock_acu.call_count)
            self.assertEqual(4, len(swcfgs))
            for swcfg in swcfgs:
                self.assertEqual(10, len(swcfg.ifaces))
                for iface in swcfg.ifaces:
                    self.assertTrue(iface.portchannel_id)
                    self.assertEqual(iface.members, [])


class TestSyncloopExtension(base.TestCase):
    def setUp(self):
        super().setUp()

        switchgroups = [
            cfix.make_switchgroup("seagull", availability_zone="qa-de-1a"),
            cfix.make_switchgroup("crow", availability_zone="qa-de-1a"),
        ]

        self.conf_drv = cfix.make_config(switchgroups=switchgroups, hostgroups=[])
        _override_driver_config(self.conf_drv)

        self.ext_mgr = extensions.ExtensionManager(fabric_ext_path[0])
        self.app = webtest.TestApp(setup_extensions_middleware(self.ext_mgr))

    def test_get_all_syncloop_status(self):
        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'get_syncloop_status') as mock_gss:
            mock_gss.return_value = "foo"
            resp = self.app.get("/cc-fabric/agent-syncloop")
            self.assertEqual({"test": "foo"}, resp.json)

    def test_get_all_syncloop_status_existing_agent_detail(self):
        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'get_syncloop_status') as mock_gss:
            mock_gss.return_value = "foo"
            resp = self.app.get("/cc-fabric/agent-syncloop/test")
            self.assertEqual("foo", resp.json)

    def test_get_all_syncloop_status_non_existing_agent_detail(self):
        self.assertRaisesRegex(webtest.app.AppError, "Object non-existent-platform not found",
                               self.app.get, "/cc-fabric/agent-syncloop/non-existent-platform")

    def test_set_syncloop_enabled(self):
        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'set_syncloop_enabled') as mock_gss:
            expected_calls = [
                mock.call(mock.ANY, False),
                mock.call(mock.ANY, False),
                mock.call(mock.ANY, True),
                mock.call(mock.ANY, True),
            ]

            for enabled in ('0', 'false', '1', 'true'):
                self.app.put(f"/cc-fabric/agent-syncloop/test?enabled={enabled}")

            mock_gss.assert_has_calls(expected_calls)
