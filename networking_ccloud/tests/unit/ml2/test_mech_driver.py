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

from operator import itemgetter
from unittest import mock

from neutron.db import segments_db
from neutron.plugins.ml2 import driver_context
from neutron.plugins.ml2 import models as ml2_models
from neutron.tests.unit.plugins.ml2 import test_plugin
from neutron_lib import context
from neutron_lib import exceptions as nl_exc
from neutron_lib.plugins import directory
from oslo_config import cfg

from networking_ccloud.common.config import _override_driver_config
from networking_ccloud.common.config import config_oslo  # noqa, make sure config opts are there
from networking_ccloud.common import constants as cc_const
from networking_ccloud.ml2.agent.common.api import CCFabricSwitchAgentRPCClient
from networking_ccloud.tests import base
from networking_ccloud.tests.common import config_fixtures as cfix


class TestCCFabricMechanismDriver(test_plugin.Ml2PluginV2TestCase, base.TestCase):
    _mechanism_drivers = [cc_const.CC_DRIVER_NAME]

    def setUp(self):
        cfg.CONF.set_override('driver_config_path', 'invalid/path/to/conf.yaml', group='ml2_cc_fabric')
        cfg.CONF.set_override('network_vlan_ranges', ['seagull:23:42', 'cat:53:1337', 'crow:200:300', 'squirrel:17:17'],
                              group='ml2_type_vlan')
        cfg.CONF.set_override('mechanism_drivers', self._mechanism_drivers, group='ml2')
        cc_const.SWITCH_AGENT_TOPIC_MAP['test'] = 'cc-fabric-switch-agent-test'

        switchgroups = [
            cfix.make_switchgroup("seagull"),
            cfix.make_switchgroup("crow"),
            cfix.make_switchgroup("cat"),
            cfix.make_switchgroup("squirrel")
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
        # FIXME: hg_squirrel
        hg_squirrel = cfix.make_metagroup("squirrel")

        hostgroups = hg_seagull + hg_crow + hg_cat + hg_squirrel

        self.conf_drv = cfix.make_config(switchgroups=switchgroups, hostgroups=hostgroups)
        _override_driver_config(self.conf_drv)

        self.setup_parent()
        self.plugin = directory.get_plugin()
        self.context = context.get_admin_context()

        mm = directory.get_plugin().mechanism_manager
        self.mech_driver = mm.mech_drivers[cc_const.CC_DRIVER_NAME].obj

        self._vxlan_segment = {'network_type': 'vxlan', 'physical_network': None,
                               'segmentation_id': 23, 'id': 'test-id'}

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

    def test_bind_port_direct_level_0(self):
        with mock.patch.object(self.mech_driver, 'handle_binding_host_added') as mock_bha:
            context = self._test_bind_port(fake_host='node001-seagull')
            context.continue_binding.assert_called()
            mock_bha.assert_not_called()
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
            # FIXME: maybe just construct the switchconfig object?
            swcfg = mock_acu.call_args[0][1]
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
        with mock.patch.object(self.mech_driver, 'handle_binding_host_added') as mock_bha:
            context = self._test_bind_port(fake_host='node001-seagull',
                                           fake_segments=fake_segments, binding_levels=binding_levels)
            context.continue_binding.assert_not_called()
            mock_bha.assert_not_called()
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

    def test_bind_port_segment_full(self):
        # vlan allocation pool full, what do?
        pass

    def test_delete_port_segment_in_use_host_in_use(self):
        pass

    def test_delete_port_segment_in_use_host_not_in_use(self):
        pass

    def test_delete_port_segment_not_in_use(self):
        pass

    def test_delete_port_with_host_that_is_in_metagroup(self):
        pass
