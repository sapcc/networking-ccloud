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

import copy
from operator import itemgetter
from unittest import mock

from neutron.db.models import address_scope as ascope_models
from neutron.db.models import tag as tag_models
from neutron.db import models_v2
from neutron.db import segments_db
from neutron.plugins.ml2 import driver_context
from neutron.plugins.ml2 import models as ml2_models
from neutron.tests.common import helpers as neutron_test_helpers
from neutron.tests.unit.plugins.ml2 import test_plugin

from neutron_lib.api.definitions import external_net as extnet_api
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib import context
from neutron_lib import exceptions as nl_exc
from neutron_lib.plugins import directory
from oslo_config import cfg

from networking_ccloud.common.config import _override_driver_config
from networking_ccloud.common.config import config_oslo  # noqa, make sure config opts are there
from networking_ccloud.common import constants as cc_const
from networking_ccloud.common import exceptions as cc_exc
from networking_ccloud.ml2.agent.common.api import CCFabricSwitchAgentRPCClient
from networking_ccloud.ml2.agent.common import messages as agent_msg
from networking_ccloud.tests import base
from networking_ccloud.tests.common import config_fixtures as cfix


class CCFabricMechanismDriverTestBase(test_plugin.Ml2PluginV2TestCase, base.PortBindingHelper, base.TestCase):
    _mechanism_drivers = [cc_const.CC_DRIVER_NAME]
    _vxlan_segment = {'network_type': 'vxlan', 'physical_network': None,
                      'segmentation_id': 23, 'id': 'test-id'}

    def _register_azs(self):
        self.agent1 = neutron_test_helpers.register_dhcp_agent(host='network-agent-a-1', az='qa-de-1a')
        self.agent2 = neutron_test_helpers.register_dhcp_agent(host='network-agent-b-1', az='qa-de-1b')
        self.agent3 = neutron_test_helpers.register_dhcp_agent(host='network-agent-c-1', az='qa-de-1c')

    def _test_bind_port(self, fake_host, fake_segments=None, network=None, subnet=None, binding_levels=None):
        if network is None:
            with self.network() as network:
                return self._test_bind_port(fake_host, fake_segments, network, binding_levels=binding_levels)
        if subnet is None:
            with self.subnet(network=network) as subnet:
                return self._test_bind_port(fake_host, fake_segments, network, subnet, binding_levels)

        with self.port(subnet=subnet) as port:
            port['port']['binding:host_id'] = fake_host
            if fake_segments is None:
                fake_segments = [self._vxlan_segment]

            with mock.patch('neutron.plugins.ml2.driver_context.PortContext.binding_levels',
                            new_callable=mock.PropertyMock) as bl_mock:
                bindings = ml2_models.PortBinding()
                pc = driver_context.PortContext(self.plugin, self.context, port['port'], network['network'],
                                                bindings, binding_levels=None)
                bl_mock.return_value = binding_levels
                pc._segments_to_bind = fake_segments

                pc.continue_binding = mock.Mock()
                pc.set_binding = mock.Mock()
                pc._plugin_context = self.context
                self.mech_driver.bind_port(pc)
                return pc


class TestCCFabricMechanismDriver(CCFabricMechanismDriverTestBase):
    def setUp(self):
        cfg.CONF.set_override('driver_config_path', 'invalid/path/to/conf.yaml', group='ml2_cc_fabric')
        cfg.CONF.set_override('network_vlan_ranges', ['seagull:23:42', 'cat:53:1337', 'crow:200:300', 'squirrel:17:17'],
                              group='ml2_type_vlan')
        cfg.CONF.set_override('mechanism_drivers', self._mechanism_drivers, group='ml2')
        cc_const.SWITCH_AGENT_TOPIC_MAP['test'] = 'cc-fabric-switch-agent-test'

        switchgroups = [
            cfix.make_switchgroup("seagull", availability_zone="qa-de-1a"),
            cfix.make_switchgroup("crow", availability_zone="qa-de-1b"),
            cfix.make_switchgroup("cat", availability_zone="qa-de-1c"),
            cfix.make_switchgroup("squirrel", availability_zone="qa-de-1d")
        ]

        # hostgroups:
        #   nova-compute-seagull - vpod
        #       metagroup, 10 hosts, 4 interfaces, 2 per switchpair, all lacp
        #   nova-compute-crow - vpod, same as seagull
        #   cat - bpod, 10 random hosts
        #   squirrel - used for vlan exhaustion test and non-lacp hosts
        hg_seagull = cfix.make_metagroup("seagull")
        hg_crow = cfix.make_metagroup("crow")
        hg_cat = cfix.make_hostgroups("cat")
        hg_squirrel = cfix.make_metagroup("squirrel")

        hostgroups = hg_seagull + hg_crow + hg_cat + hg_squirrel

        extra_vrfs = [{"name": "cc-earth", "address_scopes": ["the-open-sea"], "number": 23}]
        self.conf_drv = cfix.make_config(switchgroups=switchgroups, hostgroups=hostgroups, extra_vrfs=extra_vrfs)
        _override_driver_config(self.conf_drv)

        self.setup_parent()
        self._register_azs()
        self.plugin = directory.get_plugin()
        self.context = context.get_admin_context()

        mm = directory.get_plugin().mechanism_manager
        self.mech_driver = mm.mech_drivers[cc_const.CC_DRIVER_NAME].obj

        ctx = context.get_admin_context()
        with ctx.session.begin(subtransactions=True):
            self._address_scope = ascope_models.AddressScope(name="the-open-sea", ip_version=4)
            ctx.session.add(self._address_scope)

    def test_bind_port_direct_level_0(self):
        with mock.patch.object(self.mech_driver, 'handle_binding_host_changed') as mock_bhc:
            context = self._test_bind_port(fake_host='node001-seagull')
            context.continue_binding.assert_called()
            mock_bhc.assert_not_called()
            context.set_binding.assert_not_called()

    def test_bind_port_direct_level_1(self):
        fake_segments = [{'id': 'fake-segment-id', 'physical_network': 'seagull', 'segmentation_id': 42,
                          'network_type': 'vlan'}]
        binding_levels = [{'driver': 'cc-fabric', 'bound_segment': self._vxlan_segment}]
        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
            context = self._test_bind_port(fake_host='node001-seagull',
                                           fake_segments=fake_segments, binding_levels=binding_levels)
            context.continue_binding.assert_not_called()
            mock_acu.assert_called()
            context.set_binding.assert_called()

            # check config
            # FIXME: maybe just construct the switchconfig object? or dump its structure to a dict?
            swcfg = mock_acu.call_args[0][1]
            self.assertEqual(agent_msg.OperationEnum.add, swcfg[0].operation)
            self.assertEqual(2, len(swcfg))
            self.assertEqual("seagull-sw1", swcfg[0].switch_name)
            self.assertEqual("seagull-sw2", swcfg[1].switch_name)
            self.assertEqual('add', swcfg[0].operation.name)
            self.assertEqual((23, 42), (swcfg[0].vxlan_maps[0].vni, swcfg[0].vxlan_maps[0].vlan))
            self.assertEqual(42, swcfg[0].ifaces[0].native_vlan)
            self.assertEqual([42], swcfg[0].ifaces[0].trunk_vlans)

    def test_bind_port_direct_level_1_broken_segment(self):
        fake_segments = [{'id': 'fake-segment-id', 'physical_network': 'invalid-physnet', 'segmentation_id': 42,
                          'network_type': 'vlan'}]
        binding_levels = [{'driver': 'cc-fabric', 'bound_segment': self._vxlan_segment}]
        with mock.patch.object(self.mech_driver, 'handle_binding_host_changed') as mock_bhc:
            context = self._test_bind_port(fake_host='node001-seagull',
                                           fake_segments=fake_segments, binding_levels=binding_levels)
            context.continue_binding.assert_not_called()
            mock_bhc.assert_not_called()
            context.set_binding.assert_not_called()

    def test_bind_port_hpb(self):
        # only one stage bound
        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
            context = self._test_bind_port(fake_host='nova-compute-seagull')
            context.continue_binding.assert_called()
            mock_acu.assert_called()
            context.set_binding.assert_not_called()

            # FIXME: check config
            swcfg = mock_acu.call_args[0][1]
            self.assertEqual(2, len(swcfg))
            self.assertEqual(10, len(swcfg[0].ifaces))

    def test_bind_port_hpb_level_1_ignored(self):
        # driver should ignore second level for non-direct groups
        fake_segments = [{'id': 'fake-segment-id', 'physical_network': 'seagull', 'segmentation_id': 42,
                          'network_type': 'vlan'}]
        binding_levels = [{'driver': 'cc-fabric', 'bound_segment': self._vxlan_segment}]
        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
            context = self._test_bind_port(fake_host='nova-compute-seagull',
                                           fake_segments=fake_segments, binding_levels=binding_levels)
            context.continue_binding.assert_not_called()
            mock_acu.assert_not_called()
            context.set_binding.assert_not_called()

    def test_bind_port_new_segment(self):
        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
            context = self._test_bind_port(fake_host='nova-compute-seagull')
            context.continue_binding.assert_called()
            mock_acu.assert_called()
            context.set_binding.assert_not_called()

    def test_bind_port_new_and_existing_segment(self):
        with self.network() as network:
            with self.subnet(network=network) as subnet:
                with mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update'):
                    context1 = self._test_bind_port(fake_host='nova-compute-seagull', network=network, subnet=subnet)
                    context1.continue_binding.assert_called()
                    context2 = self._test_bind_port(fake_host='node001-seagull', network=network, subnet=subnet)
                    context2.continue_binding.assert_called()
                    # segment looks different, depending on if it was created or if it already existed
                    #   --> compare first arg and second arg separately
                    self.assertEqual(context1.continue_binding.call_args[0][0],
                                     context2.continue_binding.call_args[0][0])
                    keyget = itemgetter('id', 'network_type', 'physical_network', 'segmentation_id')
                    self.assertEqual(keyget(context1.continue_binding.call_args[0][1][0]),
                                     keyget(context2.continue_binding.call_args[0][1][0]))
                    segment_id = context1.continue_binding.call_args[0][1][0]['id']
                    segment = segments_db.get_segment_by_id(self.context, segment_id)
                    self.assertEqual('seagull', segment['physical_network'])

    def test_bind_port_vlan_exhaustion(self):
        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update'):
            context1 = self._test_bind_port(fake_host='nova-compute-squirrel')
            context1.continue_binding.assert_called()
        self.assertRaises(nl_exc.NoNetworkAvailable, self._test_bind_port, fake_host='nova-compute-squirrel')

    def test_bind_port_metagroup(self):
        pass

    def test_bind_port_metagroup_with_exception(self):
        pass

    def test_bind_port_host_not_found(self):
        context = self._test_bind_port('unkown_host')
        context.continue_binding.assert_not_called()
        context.set_binding.assert_not_called()

    def test_delete_port_segment_in_use_host_in_use(self):
        net = self._make_network(name="a", admin_state_up=True, fmt='json')['network']
        seg_0 = {'network_id': net['id'], 'network_type': 'vxlan', 'segmentation_id': 232323}
        seg_1 = {'network_id': net['id'], 'network_type': 'vlan', 'physical_network': 'seagull',
                 'segmentation_id': 1000}
        segments_db.add_network_segment(self.context, net['id'], seg_0)
        segments_db.add_network_segment(self.context, net['id'], seg_1, 1, True)
        self._port_a_1 = self._make_port_with_binding(segments=[(seg_0, 'cc-fabric'),
                                                                (seg_1, 'cat-ml2')],
                                                      host='nova-compute-seagull')

        with self.subnet(network=dict(network=net)) as subnet:
            with self.port(subnet=subnet) as port:
                port['port']['binding:host_id'] = "nova-compute-seagull"
                with mock.patch('neutron.plugins.ml2.driver_context.PortContext.binding_levels',
                                new_callable=mock.PropertyMock) as bl_mock, \
                        mock.patch.object(self.mech_driver, 'handle_binding_host_changed') as mock_bhc:
                    bindings = ml2_models.PortBinding()
                    pc = driver_context.PortContext(self.plugin, self.context, port['port'], net,
                                                    bindings, binding_levels=None)
                    bl_mock.return_value = [dict(bound_segment=seg_0), dict(bound_segment=seg_1)]

                    pc.release_dynamic_segment = mock.Mock()
                    pc._plugin_context = self.context
                    self.mech_driver.delete_port_postcommit(pc)
                    pc.release_dynamic_segment.assert_not_called()
                    mock_bhc.assert_not_called()

    def test_delete_port_segment_in_use_host_not_in_use(self):
        # segment + one active port binding with same binding host as is deleted
        net = self._make_network(name="a", admin_state_up=True, fmt='json')['network']
        seg_0 = {'network_id': net['id'], 'network_type': 'vxlan', 'segmentation_id': 232323}
        seg_1 = {'network_id': net['id'], 'network_type': 'vlan', 'physical_network': 'seagull',
                 'segmentation_id': 1000}
        segments_db.add_network_segment(self.context, net['id'], seg_0)
        segments_db.add_network_segment(self.context, net['id'], seg_1, 1, True)
        self._port_a_1 = self._make_port_with_binding(segments=[(seg_0, 'cc-fabric'),
                                                                (seg_1, 'cat-ml2')],
                                                      host='node001-seagull')

        with self.subnet(network=dict(network=net)) as subnet:
            with self.port(subnet=subnet) as port:
                port['port']['binding:host_id'] = "node002-seagull"
                with mock.patch('neutron.plugins.ml2.driver_context.PortContext.binding_levels',
                                new_callable=mock.PropertyMock) as bl_mock, \
                        mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
                    bindings = ml2_models.PortBinding()
                    pc = driver_context.PortContext(self.plugin, self.context, port['port'], net,
                                                    bindings, binding_levels=None)
                    bl_mock.return_value = [dict(bound_segment=seg_0), dict(bound_segment=seg_1)]

                    pc.release_dynamic_segment = mock.Mock()
                    pc._plugin_context = self.context
                    self.mech_driver.delete_port_postcommit(pc)
                    pc.release_dynamic_segment.assert_not_called()
                    mock_acu.assert_called()
                    swcfgs = mock_acu.call_args[0][1]
                    for swcfg in swcfgs:
                        self.assertEqual(agent_msg.OperationEnum.remove, swcfg.operation)
                        # no vlan updates!
                        self.assertIsNone(swcfg.vlans)
                        self.assertIsNone(swcfg.vxlan_maps)
                        self.assertIsNone(swcfg.bgp)
                        for iface in swcfg.ifaces:
                            self.assertEqual([seg_1['segmentation_id']], iface.trunk_vlans)

    def test_delete_port_segment_not_in_use(self):
        net = self._make_network(name="a", admin_state_up=True, fmt='json')['network']
        seg_0 = {'network_id': net['id'], 'network_type': 'vxlan', 'segmentation_id': 232323}
        seg_1 = {'network_id': net['id'], 'network_type': 'vlan', 'physical_network': 'seagull',
                 'segmentation_id': 1000}
        segments_db.add_network_segment(self.context, net['id'], seg_0)
        segments_db.add_network_segment(self.context, net['id'], seg_1, 1, True)
        with self.subnet(network=dict(network=net)) as subnet:
            with self.port(subnet=subnet) as port:
                port['port']['binding:host_id'] = "nova-compute-seagull"
                with mock.patch('neutron.plugins.ml2.driver_context.PortContext.binding_levels',
                                new_callable=mock.PropertyMock) as bl_mock, \
                        mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
                    bindings = ml2_models.PortBinding()
                    pc = driver_context.PortContext(self.plugin, self.context, port['port'], net,
                                                    bindings, binding_levels=None)
                    bl_mock.return_value = [dict(bound_segment=seg_0), dict(bound_segment=seg_1)]

                    pc.release_dynamic_segment = mock.Mock()
                    pc._plugin_context = self.context
                    self.mech_driver.delete_port_postcommit(pc)
                    pc.release_dynamic_segment.assert_called()
                    self.assertEqual(seg_1['id'], pc.release_dynamic_segment.call_args[0][0])
                    mock_acu.assert_called()
                    swcfgs = mock_acu.call_args[0][1]
                    for swcfg in swcfgs:
                        self.assertEqual(agent_msg.OperationEnum.remove, swcfg.operation)
                        self.assertEqual([seg_1['segmentation_id']], [v.vlan for v in swcfg.vlans])
                        self.assertEqual([(seg_0['segmentation_id'], seg_1['segmentation_id'])],
                                         [(m.vni, m.vlan) for m in swcfg.vxlan_maps])
                        self.assertEqual([seg_1['segmentation_id']], [v.vlan for v in swcfg.bgp.vlans])
                        for iface in swcfg.ifaces:
                            self.assertEqual([seg_1['segmentation_id']], iface.trunk_vlans)

    def test_delete_port_with_host_that_is_in_metagroup(self):
        net = self._make_network(name="a", admin_state_up=True, fmt='json')['network']
        seg_0 = {'network_id': net['id'], 'network_type': 'vxlan', 'segmentation_id': 232323}
        seg_1 = {'network_id': net['id'], 'network_type': 'vlan', 'physical_network': 'seagull',
                 'segmentation_id': 1000}
        segments_db.add_network_segment(self.context, net['id'], seg_0)
        segments_db.add_network_segment(self.context, net['id'], seg_1, 1, True)
        self._port_a_1 = self._make_port_with_binding(segments=[(seg_0, 'cc-fabric'),
                                                                (seg_1, 'cat-ml2')],
                                                      host='node001-seagull')
        with self.subnet(network=dict(network=net)) as subnet:
            with self.port(subnet=subnet) as port:
                port['port']['binding:host_id'] = "nova-compute-seagull"
                with mock.patch('neutron.plugins.ml2.driver_context.PortContext.binding_levels',
                                new_callable=mock.PropertyMock) as bl_mock, \
                        mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
                    bindings = ml2_models.PortBinding()
                    pc = driver_context.PortContext(self.plugin, self.context, port['port'], net,
                                                    bindings, binding_levels=None)
                    bl_mock.return_value = [dict(bound_segment=seg_0), dict(bound_segment=seg_1)]

                    pc.release_dynamic_segment = mock.Mock()
                    pc._plugin_context = self.context
                    self.mech_driver.delete_port_postcommit(pc)
                    pc.release_dynamic_segment.assert_not_called()
                    mock_acu.assert_called()
                    swcfgs = mock_acu.call_args[0][1]
                    for swcfg in swcfgs:
                        self.assertEqual(agent_msg.OperationEnum.remove, swcfg.operation)
                        # make sure Port-Channel101 of node001-seagull is not part of this
                        self.assertEqual([f"Port-Channel{n}" for n in range(102, 111)],
                                         [iface.name for iface in swcfg.ifaces])

    def test_delete_port_with_no_binding_levels(self):
        # segment + one active port binding with same binding host as is deleted
        with self.port() as port:
            port['port']['binding:host_id'] = "node002-seagull"
            with mock.patch('neutron.plugins.ml2.driver_context.PortContext.binding_levels',
                            new_callable=mock.PropertyMock) as bl_mock, \
                    mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
                bindings = ml2_models.PortBinding()
                pc = driver_context.PortContext(self.plugin, self.context, port['port'], {'id': 'asdf'},
                                                bindings, binding_levels=None)
                bl_mock.return_value = []

                pc.release_dynamic_segment = mock.Mock()
                pc._plugin_context = self.context
                self.mech_driver.delete_port_postcommit(pc)
                pc.release_dynamic_segment.assert_not_called()
                mock_acu.assert_not_called()

    def test_update_port_to_host_to_same_host(self):
        net = self._make_network(name="a", admin_state_up=True, fmt='json')['network']
        seg_0 = {'network_id': net['id'], 'network_type': 'vxlan', 'segmentation_id': 232323}
        seg_1 = {'network_id': net['id'], 'network_type': 'vlan', 'physical_network': 'seagull',
                 'segmentation_id': 1000}
        segments_db.add_network_segment(self.context, net['id'], seg_0)
        segments_db.add_network_segment(self.context, net['id'], seg_1, 1, True)
        self._port_a_1 = self._make_port_with_binding(segments=[(seg_0, 'cc-fabric'),
                                                                (seg_1, 'cat-ml2')],
                                                      host='node001-seagull')
        with self.subnet(network=dict(network=net)) as subnet:
            with self.port(subnet=subnet) as port:
                port['port']['binding:host_id'] = "nova-compute-seagull"
                with mock.patch('networking_ccloud.ml2.mech_driver.CCFabricMechanismDriver.'
                                'driver_handle_binding_host_removed') as hbh_mock:
                    bindings = ml2_models.PortBinding()
                    pc = driver_context.PortContext(self.plugin, self.context, port['port'], net,
                                                    bindings, binding_levels=None,
                                                    original_port=port['port'])

                    pc._plugin_context = self.context
                    self.mech_driver.update_port_postcommit(pc)
                    hbh_mock.assert_not_called()

    def test_update_port_to_dummy_host(self):
        net = self._make_network(name="a", admin_state_up=True, fmt='json')['network']
        seg_0 = {'network_id': net['id'], 'network_type': 'vxlan', 'segmentation_id': 232323}
        seg_1 = {'network_id': net['id'], 'network_type': 'vlan', 'physical_network': 'seagull',
                 'segmentation_id': 2000}
        segments_db.add_network_segment(self.context, net['id'], seg_0)
        segments_db.add_network_segment(self.context, net['id'], seg_1, 1, True)
        with self.subnet(network=dict(network=net)) as subnet:
            with self.port(subnet=subnet) as port:
                old_port = copy.deepcopy(port)
                old_port['port']['binding:host_id'] = "nova-compute-seagull"
                port['port']['binding:host_id'] = "dummy"
                with mock.patch('neutron.plugins.ml2.driver_context.PortContext.original_binding_levels',
                                new_callable=mock.PropertyMock) as bl_mock, \
                        mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
                    bl_mock.return_value = [dict(bound_segment=seg_0), dict(bound_segment=seg_1)]
                    nc = driver_context.NetworkContext(self.plugin, self.context, net, net)
                    bindings = ml2_models.PortBinding()
                    pc = driver_context.PortContext(self.plugin, self.context, port['port'], nc,
                                                    bindings, binding_levels=None,
                                                    original_port=old_port['port'])
                    pc.release_dynamic_segment = mock.Mock()
                    pc._plugin_context = self.context
                    self.mech_driver.update_port_postcommit(pc)
                    pc.release_dynamic_segment.assert_called()
                    self.assertEqual(seg_1['id'], pc.release_dynamic_segment.call_args[0][0])
                    mock_acu.assert_called()

    def test_update_port_from_unbound(self):
        with self.port() as port:
            old_port = copy.deepcopy(port)
            old_port['port']['binding:host_id'] = "nova-compute-seagull"
            port['port']['binding:host_id'] = "dummy"
            with mock.patch('neutron.plugins.ml2.driver_context.PortContext.original_binding_levels',
                            new_callable=mock.PropertyMock) as bl_mock, \
                    mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
                bl_mock.return_value = []
                nc = driver_context.NetworkContext(self.plugin, self.context, {'id': 'asdf'}, {'id': 'qwertz'})
                bindings = ml2_models.PortBinding()
                pc = driver_context.PortContext(self.plugin, self.context, port['port'], nc,
                                                bindings, binding_levels=None,
                                                original_port=old_port['port'])
                pc.release_dynamic_segment = mock.Mock()
                pc._plugin_context = self.context
                self.mech_driver.update_port_postcommit(pc)
                pc.release_dynamic_segment.assert_not_called()
                mock_acu.assert_not_called()

    def test_create_network_multiple_az_hints_fail(self):
        res = self._create_network(self.fmt, "net1", admin_state_up=True,
                                   availability_zone_hints=["qa-de-1a", "qa-de-1b"])
        self.assertEqual(res.status_int, 400)
        self.assertEqual(res.json["NeutronError"]["type"], "OnlyOneAZHintAllowed")

    def test_create_network_az_hint_not_in_driver_config(self):
        self.agent_not_in_cfg = neutron_test_helpers.register_dhcp_agent(host='network-agent-y-1', az='qa-de-1y')
        import networking_ccloud
        with mock.patch.object(networking_ccloud.ml2.mech_driver.CCFabricMechanismDriver, 'create_network_precommit',
                               wraps=self.mech_driver.create_network_precommit) as cnp:
            res = self._create_network(self.fmt, "net1", admin_state_up=True,
                                       availability_zone_hints=["qa-de-1y"])
            cnp.assert_called()
            self.assertEqual(res.status_int, 404)
            self.assertEqual(res.json["NeutronError"]["type"], "AvailabilityZoneNotFound")

    def test_bind_port_az_hint_fail_on_mismatch(self):
        with self.network(availability_zone_hints=["qa-de-1b"]) as network:
            with self.subnet(network=network):
                res = self._create_port(self.fmt, network['network']['id'], expected_res=400,
                                        arg_list=('binding:host_id',), **{'binding:host_id': 'node001-seagull'})
                self.assertEqual(res.json["NeutronError"]["type"], "HostNetworkAZAffinityError")

    def test_bind_port_az_hint_match(self):
        with self.network(availability_zone_hints=["qa-de-1a"]) as network:
            with self.subnet(network=network):
                with mock.patch('neutron.plugins.ml2.plugin.Ml2Plugin._after_create_port') as acp:
                    acp.return_value = {}
                    res = self._create_port(self.fmt, network['network']['id'], expected_res=200,
                                            arg_list=('binding:host_id',), **{'binding:host_id': 'node001-seagull'})
                    acp.assert_called()
                    self.assertEqual(res.status_int, 201)

    def test_bind_port_external_network(self):
        net_kwargs = {'arg_list': (extnet_api.EXTERNAL,), extnet_api.EXTERNAL: True}
        with self.network(**net_kwargs) as network:
            with self.subnetpool(["1.1.0.0/16", "1.2.0.0/24"], address_scope_id=self._address_scope.id, name="foo",
                                 tenant_id="foo", admin=True) as snp:
                with self.subnet(network=network, cidr="1.1.1.0/24", gateway_ip="1.1.1.1",
                                 subnetpool_id=snp['subnetpool']['id']) as subnet:
                    with mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
                        context1 = self._test_bind_port(fake_host='nova-compute-seagull',
                                                        network=network, subnet=subnet)
                        context1.continue_binding.assert_called()
                        mock_acu.assert_called()
                        swcfgs = mock_acu.call_args[0][1]
                        for swcfg in swcfgs:
                            # check for vlan ids
                            vlan_id = swcfg.bgp.vlans[0].vlan
                            self.assertEqual([
                                agent_msg.VlanIface(vlan=vlan_id, vrf="cc-earth", primary_ip="1.1.1.1/24",
                                                    secondary_ips=[]),
                            ], swcfg.vlan_ifaces)

                            # check bgp config
                            self.assertEqual([
                                agent_msg.BGPVRF(
                                    name="cc-earth",
                                    networks=[
                                        agent_msg.BGPVRFNetwork(network='1.1.1.0/24',
                                                                az_local=False, ext_announcable=False),
                                    ],
                                    aggregates=[
                                        agent_msg.BGPVRFAggregate(network='1.1.0.0/16', az_local=False),
                                        agent_msg.BGPVRFAggregate(network='1.2.0.0/24', az_local=False),
                                    ],
                                ),
                            ], swcfg.bgp.vrfs)

    def test_bind_port_external_network_with_ext_announcable(self):
        net_kwargs = {'arg_list': (extnet_api.EXTERNAL,), extnet_api.EXTERNAL: True}
        with self.network(**net_kwargs) as network:
            with self.subnetpool(["1.1.1.0/24", "1.2.0.0/24"], address_scope_id=self._address_scope.id, name="foo",
                                 tenant_id="foo", admin=True) as snp:
                with self.subnet(network=network, cidr="1.1.1.0/24", gateway_ip="1.1.1.1",
                                 subnetpool_id=snp['subnetpool']['id']) as subnet:
                    with mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
                        context1 = self._test_bind_port(fake_host='nova-compute-seagull',
                                                        network=network, subnet=subnet)
                        context1.continue_binding.assert_called()
                        mock_acu.assert_called()
                        swcfgs = mock_acu.call_args[0][1]
                        for swcfg in swcfgs:
                            # check for vlan ids
                            vlan_id = swcfg.bgp.vlans[0].vlan
                            self.assertEqual([
                                agent_msg.VlanIface(vlan=vlan_id, vrf="cc-earth", primary_ip="1.1.1.1/24",
                                                    secondary_ips=[]),
                            ], swcfg.vlan_ifaces)

                            # check bgp config
                            self.assertEqual([
                                agent_msg.BGPVRF(
                                    name="cc-earth",
                                    networks=[
                                        agent_msg.BGPVRFNetwork(network='1.1.1.0/24',
                                                                az_local=False, ext_announcable=True),
                                    ],
                                    aggregates=[
                                        agent_msg.BGPVRFAggregate(network='1.2.0.0/24', az_local=False),
                                    ],
                                ),
                            ], swcfg.bgp.vrfs)

    def test_bind_port_external_network_az_local(self):
        ctx = context.get_admin_context()
        net_kwargs = {'arg_list': (extnet_api.EXTERNAL,), extnet_api.EXTERNAL: True}
        with self.network(availability_zone_hints=["qa-de-1a"], **net_kwargs) as network:
            with self.subnetpool(["1.1.0.0/16", "1.2.0.0/24"], address_scope_id=self._address_scope.id, name="foo",
                                 tenant_id="foo", admin=True) as snp:
                with ctx.session.begin():
                    snp_db = ctx.session.query(models_v2.SubnetPool).get(snp['subnetpool']['id'])
                    ctx.session.add(tag_models.Tag(standard_attr_id=snp_db.standard_attr_id,
                                    tag="availability-zone::qa-de-1a"))

                with self.subnet(network=network, cidr="1.1.1.0/24", gateway_ip="1.1.1.1",
                                 subnetpool_id=snp['subnetpool']['id']) as subnet:
                    with mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
                        context1 = self._test_bind_port(fake_host='nova-compute-seagull',
                                                        network=network, subnet=subnet)
                        context1.continue_binding.assert_called()
                        mock_acu.assert_called()
                        swcfgs = mock_acu.call_args[0][1]
                        for swcfg in swcfgs:
                            # check for vlan ids
                            vlan_id = swcfg.bgp.vlans[0].vlan
                            self.assertEqual([
                                agent_msg.VlanIface(vlan=vlan_id, vrf="cc-earth", primary_ip="1.1.1.1/24",
                                                    secondary_ips=[]),
                            ], swcfg.vlan_ifaces)

                            # check bgp config
                            self.assertEqual([
                                agent_msg.BGPVRF(
                                    name="cc-earth",
                                    networks=[
                                        agent_msg.BGPVRFNetwork(network='1.1.1.0/24',
                                                                az_local=True, ext_announcable=False),
                                    ],
                                    aggregates=[
                                        agent_msg.BGPVRFAggregate(network='1.1.0.0/16', az_local=True),
                                        agent_msg.BGPVRFAggregate(network='1.2.0.0/24', az_local=True),
                                    ],
                                ),
                            ], swcfg.bgp.vrfs)

    def test_delete_port_external_network_segment_not_in_use(self):
        net_kwargs = {'arg_list': (extnet_api.EXTERNAL,), extnet_api.EXTERNAL: True}
        with self.network(**net_kwargs) as network:
            # create existing binding, so we have something to delete
            seg_0 = {'network_id': network['network']['id'], 'network_type': 'vxlan', 'segmentation_id': 232323}
            seg_1 = {'network_id': network['network']['id'], 'network_type': 'vlan', 'physical_network': 'seagull',
                     'segmentation_id': 1000}
            segments_db.add_network_segment(self.context, network['network']['id'], seg_0)
            segments_db.add_network_segment(self.context, network['network']['id'], seg_1, 1, True)
            with self.subnetpool(["1.1.0.0/16", "1.2.0.0/24"], address_scope_id=self._address_scope.id, name="foo",
                                 tenant_id="foo", admin=True) as snp:
                with self.subnet(network=network, cidr="1.1.1.0/24", gateway_ip="1.1.1.1",
                                 subnetpool_id=snp['subnetpool']['id']) as subnet:
                    with self.port(subnet=subnet) as port:
                        port['port']['binding:host_id'] = "nova-compute-seagull"
                        with mock.patch('neutron.plugins.ml2.driver_context.PortContext.binding_levels',
                                        new_callable=mock.PropertyMock) as bl_mock, \
                                mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
                            bindings = ml2_models.PortBinding()
                            pc = driver_context.PortContext(self.plugin, self.context, port['port'], network['network'],
                                                            bindings, binding_levels=None)
                            bl_mock.return_value = [dict(bound_segment=seg_0), dict(bound_segment=seg_1)]

                            pc.release_dynamic_segment = mock.Mock()
                            pc._plugin_context = self.context
                            self.mech_driver.delete_port_postcommit(pc)
                            pc.release_dynamic_segment.assert_called()
                            self.assertEqual(seg_1['id'], pc.release_dynamic_segment.call_args[0][0])
                            mock_acu.assert_called()
                            swcfgs = mock_acu.call_args[0][1]

                            for swcfg in swcfgs:
                                self.assertEqual(agent_msg.OperationEnum.remove, swcfg.operation)

                                # check for vlan ids
                                vlan_id = swcfg.bgp.vlans[0].vlan
                                self.assertEqual([
                                    agent_msg.VlanIface(vlan=vlan_id, vrf="cc-earth", primary_ip="1.1.1.1/24",
                                                        secondary_ips=[]),
                                ], swcfg.vlan_ifaces)

                                # check bgp config
                                self.assertEqual([
                                    agent_msg.BGPVRF(
                                        name="cc-earth",
                                        networks=[
                                            agent_msg.BGPVRFNetwork(network='1.1.1.0/24',
                                                                    az_local=False, ext_announcable=False),
                                        ],
                                        # no aggregates on delete
                                        aggregates=[],
                                    ),
                                ], swcfg.bgp.vrfs)


class TestCCFabricMechanismDriverInterconnects(CCFabricMechanismDriverTestBase):
    def setUp(self):
        cfg.CONF.set_override('driver_config_path', 'invalid/path/to/conf.yaml', group='ml2_cc_fabric')
        cfg.CONF.set_override('network_vlan_ranges', ['seagull:23:42', 'cat:53:1337', 'crow:200:300',
                                                      'transit1:1000:2000', 'transit2:1000:2000',
                                                      'bgw1:1000:2000', 'bgw2:1000:2000', 'bgw3:1000:2000'],
                              group='ml2_type_vlan')
        cfg.CONF.set_override('mechanism_drivers', self._mechanism_drivers, group='ml2')
        cc_const.SWITCH_AGENT_TOPIC_MAP['test'] = 'cc-fabric-switch-agent-test'

        switchgroups = [
            cfix.make_switchgroup("seagull", availability_zone="qa-de-1a"),
            cfix.make_switchgroup("transit1", availability_zone="qa-de-1a"),
            cfix.make_switchgroup("bgw1", availability_zone="qa-de-1a"),

            cfix.make_switchgroup("crow", availability_zone="qa-de-1b"),
            cfix.make_switchgroup("transit2", availability_zone="qa-de-1b"),
            cfix.make_switchgroup("bgw2", availability_zone="qa-de-1b"),

            cfix.make_switchgroup("cat", availability_zone="qa-de-1c"),
            cfix.make_switchgroup("bgw3", availability_zone="qa-de-1c"),
        ]

        # hostgroups
        hg_seagull = cfix.make_metagroup("seagull")
        hg_crow = cfix.make_metagroup("crow")
        hg_cat = cfix.make_metagroup("cat")
        interconnects = [
            cfix.make_interconnect(cc_const.DEVICE_TYPE_TRANSIT, "transit-host1", "transit1", ["qa-de-1a"]),
            cfix.make_interconnect(cc_const.DEVICE_TYPE_BGW, "bgw-host1", "bgw1", ["qa-de-1a"]),
            cfix.make_interconnect(cc_const.DEVICE_TYPE_TRANSIT, "transit-host2", "transit2", ["qa-de-1b", "qa-de-1c"]),
            cfix.make_interconnect(cc_const.DEVICE_TYPE_BGW, "bgw-host2", "bgw2", ["qa-de-1b"]),
            cfix.make_interconnect(cc_const.DEVICE_TYPE_BGW, "bgw-host3", "bgw3", ["qa-de-1c"]),
        ]
        self._ic_devices = ["bgw1", "bgw2", "bgw3", "transit1", "transit2", "transit2"]
        self._ic_hosts = ["bgw-host1", "bgw-host2", "bgw-host3", "transit-host1", "transit-host2", "transit-host2"]

        hostgroups = hg_seagull + hg_crow + hg_cat + interconnects

        self.conf_drv = cfix.make_config(switchgroups=switchgroups, hostgroups=hostgroups)
        _override_driver_config(self.conf_drv)

        self.setup_parent()
        self._register_azs()
        self.plugin = directory.get_plugin()
        self.context = context.get_admin_context()

        mm = directory.get_plugin().mechanism_manager
        self.mech_driver = mm.mech_drivers[cc_const.CC_DRIVER_NAME].obj

    def test_transit_bgw_allocated_on_network_create(self):
        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
            net_attrs = {pnet.NETWORK_TYPE: "vxlan", pnet.SEGMENTATION_ID: 23}
            net = self._make_network(self.fmt, "net1", True,
                                     arg_list=(pnet.NETWORK_TYPE, pnet.SEGMENTATION_ID),
                                     **net_attrs)['network']
            mock_acu.assert_called()

            # check DB
            interconnects = self.mech_driver.fabric_plugin.get_interconnects(self.context, net['id'])
            self.assertEqual(self._ic_hosts, sorted(d.host for d in interconnects))

            # check config
            swcfg = mock_acu.call_args[0][1]
            self.assertEqual(5, len(swcfg))
            self.assertEqual(sorted({f"{dev}-sw1" for dev in self._ic_devices}),
                             sorted([s.switch_name for s in swcfg]))
            for s in swcfg:
                self.assertEqual(agent_msg.OperationEnum.add, s.operation)
                self.assertEqual(1, len(s.vlans), "Only one VLAN config expected")
                self.assertEqual(1, len(s.bgp.vlans))
                if s.switch_name.startswith("bgw"):
                    self.assertTrue(s.bgp.vlans[0].rd_evpn_domain_all)
                # bgws don't have any interfaces
                # transits are currently marked as unmanaged by default
                # --> both don't have any iface config attached
                self.assertIsNone(s.ifaces)

    def test_transit_bgw_deallocation_on_network_delete(self):
        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
            # allocate (prerequisite for test)
            net_attrs = {pnet.NETWORK_TYPE: "vxlan", pnet.SEGMENTATION_ID: 23}
            net = self._make_network(self.fmt, "net1", True,
                                     arg_list=(pnet.NETWORK_TYPE, pnet.SEGMENTATION_ID),
                                     **net_attrs)['network']
            mock_acu.assert_called()

        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
            # actual deletion test
            req = self.new_delete_request('networks', net['id'])
            res = req.get_response(self.api)
            self.assertEqual(204, res.status_int)
            mock_acu.assert_called()

            # check config
            swcfg = mock_acu.call_args[0][1]
            self.assertEqual(5, len(swcfg))
            self.assertEqual(sorted({f"{dev}-sw1" for dev in self._ic_devices}),
                             sorted([s.switch_name for s in swcfg]))
            for s in swcfg:
                self.assertEqual(agent_msg.OperationEnum.remove, s.operation)

    def test_transit_no_bgw_allocation_and_only_one_transit_for_az_hints(self):
        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
            net_attrs = {pnet.NETWORK_TYPE: "vxlan", pnet.SEGMENTATION_ID: 23}
            net = self._make_network(self.fmt, "net1", True,
                                     availability_zone_hints=["qa-de-1a"],
                                     arg_list=(pnet.NETWORK_TYPE, pnet.SEGMENTATION_ID),
                                     **net_attrs)['network']
            mock_acu.assert_called()

            # no BGWs
            bgws = self.mech_driver.fabric_plugin.get_bgws_for_network(self.context, net['id'])
            self.assertEqual([], bgws)

            # only one transit, in AZ
            transits = self.mech_driver.fabric_plugin.get_transits_for_network(self.context, net['id'])
            self.assertEqual(1, len(transits))
            self.assertEqual("qa-de-1a", transits[0].availability_zone)

    def test_transit_no_bgw_allocation_and_no_transit_if_transit_is_in_other_az(self):
        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
            net_attrs = {pnet.NETWORK_TYPE: "vxlan", pnet.SEGMENTATION_ID: 23}
            net = self._make_network(self.fmt, "net1", True,
                                     availability_zone_hints=["qa-de-1c"],
                                     arg_list=(pnet.NETWORK_TYPE, pnet.SEGMENTATION_ID),
                                     **net_attrs)['network']

            # no device available --> no config update
            mock_acu.assert_not_called()

            # no BGWs
            bgws = self.mech_driver.fabric_plugin.get_bgws_for_network(self.context, net['id'])
            self.assertEqual([], bgws)

            # only one transit, in AZ
            transits = self.mech_driver.fabric_plugin.get_transits_for_network(self.context, net['id'])
            self.assertEqual([], transits)

    def test_cannot_bind_port_with_special_device_binding_host(self):
        with mock.patch.object(self.mech_driver, 'handle_binding_host_changed') as mock_bhc:
            for host in 'transit-host1', 'bgw-host1':
                self.assertRaises(cc_exc.SpecialDevicesBindingProhibited, self._test_bind_port, fake_host=host)
                mock_bhc.assert_not_called()

    def test_publish_event_on_transit_allocation(self):
        with mock.patch.object(CCFabricSwitchAgentRPCClient, 'apply_config_update') as mock_acu:
            # our method to receive the hook
            fake_method = mock.Mock()
            try:
                registry.subscribe(fake_method, cc_const.CC_TRANSIT, events.AFTER_CREATE)

                # allocate (prerequisite for test)
                net_attrs = {pnet.NETWORK_TYPE: "vxlan", pnet.SEGMENTATION_ID: 23}
                net = self._make_network(self.fmt, "net1", True,
                                         arg_list=(pnet.NETWORK_TYPE, pnet.SEGMENTATION_ID),
                                         **net_attrs)['network']
                mock_acu.assert_called()

                self.assertEqual(2, fake_method.call_count)
                hosts = set()
                physnets = set()
                for call in fake_method.call_args_list:
                    args, kwargs = call
                    self.assertEqual((cc_const.CC_TRANSIT, events.AFTER_CREATE, self.mech_driver.fabric_plugin), args)
                    payload = kwargs['payload']
                    self.assertEqual(net['id'], payload.metadata['network_id'])
                    hosts.add(payload.metadata['host'])
                    physnets.add(payload.metadata['physical_network'])
                self.assertEqual({"transit-host1", "transit-host2"}, hosts)
                self.assertEqual({"transit1", "transit2"}, physnets)
            finally:
                registry.unsubscribe(fake_method, cc_const.CC_TRANSIT, events.AFTER_CREATE)
