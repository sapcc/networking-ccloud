# Copyright 2026 SAP SE
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

from neutron.plugins.ml2 import models as ml2_models
from neutron.services.trunk import exceptions as trunk_exc
from neutron.services.trunk import models as trunk_models
from neutron.services.trunk import plugin as trunk_plugin
from neutron_lib.callbacks import exceptions as nl_cb_exc
from neutron_lib import context
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_log import log as logging

from networking_ccloud.common.config import _override_driver_config
from networking_ccloud.common.config import config_driver
from networking_ccloud.common import constants as cc_const
from networking_ccloud.tests.common import config_fixtures as cfix
from networking_ccloud.tests.unit.ml2.test_mech_driver import CCFabricMechanismDriverTestBase


LOG = logging.getLogger(__name__)


class TestTrunkPlugin(CCFabricMechanismDriverTestBase):
    def setUp(self):
        cfg.CONF.set_override('driver_config_path', 'invalid/path/to/conf.yaml', group='ml2_cc_fabric')
        cfg.CONF.set_override('network_vlan_ranges', ['seagull:23:42'],
                              group='ml2_type_vlan')
        cfg.CONF.set_override('mechanism_drivers', self._mechanism_drivers, group='ml2')
        cc_const.SWITCH_AGENT_TOPIC_MAP['test'] = 'cc-fabric-switch-agent-test'

        switchgroups = [
            cfix.make_switchgroup("seagull", availability_zone="qa-de-1a"),
        ]

        hg_seagull_direct_multitrunk = config_driver.Hostgroup(binding_hosts=["node-multitrunk-seagull"],
                                                               members=[config_driver.SwitchPort(switch="seagull-sw1",
                                                                                                 name="e1/1/1")],
                                                               allow_multiple_trunk_ports=True)
        hg_seagull = cfix.make_metagroup("seagull") + [hg_seagull_direct_multitrunk]

        hostgroups = hg_seagull

        extra_vrfs = [{"name": "cc-earth", "address_scopes": ["the-open-sea"], "number": 23}]
        self.conf_drv = cfix.make_config(switchgroups=switchgroups, hostgroups=hostgroups, extra_vrfs=extra_vrfs)
        _override_driver_config(self.conf_drv)

        self.setup_parent()
        self._register_azs()
        self.plugin = directory.get_plugin()

        mm = directory.get_plugin().mechanism_manager
        self.mech_driver = mm.mech_drivers[cc_const.CC_DRIVER_NAME].obj

        # NOTE(seba): in our trunk driver inside the precommit hook calling
        # plugin.get_port() calls _make_port_dict(), which then calls resource
        # extenders, which then call _extend_port_trunk_details(), which THEN
        # calls get_admin_context() to query subports from the DB, which
        # _THEN_, due to this creating a new session inside the active
        # transaction, seems to break the current transaction. This only seems
        # to happen within the tests where we use sqlite. I could not reproduce
        # this in production with mariadb as database. Therefore I chose to
        # mock away this resource extender, as we are currently not using
        # this data inside the tests and it is only causing problems.
        # Fixes for the future for this problem would be to either get the
        # get_admin_context() out of the extender or find out why it breaks
        # with sqlite and fix this in the tests.
        self.re_patcher = mock.patch('neutron.services.trunk.plugin.TrunkPlugin._extend_port_trunk_details')
        self.addCleanup(self.re_patcher.stop)
        self.re_patcher.start()

        self.trunk_plugin = trunk_plugin.TrunkPlugin()
        self.trunk_plugin.add_segmentation_type('vlan', lambda x: True)
        directory.add_plugin('trunk', self.trunk_plugin)

    def _update_vif_type(self, ctx, port_or_port_id, host=None):
        if isinstance(port_or_port_id, dict):
            port_id = port_or_port_id['port']['id']
        else:
            port_id = port_or_port_id

        with ctx.session.begin():
            binding = (ctx.session.query(ml2_models.PortBinding)
                       .filter(ml2_models.PortBinding.port_id == port_id).first())
            binding.vif_type = 'cc-fabric'
            if host:
                binding.host = host
            ctx.session.add(binding)

    def test_create_trunk_for_metagroup(self):
        with self.port() as trunk_port:
            ctx = context.get_admin_context()
            self._update_vif_type(ctx, trunk_port, host='nova-compute-seagull')
            trunk = {'port_id': trunk_port['port']['id'],
                     'project_id': 'test_tenant',
                     'sub_ports': []}
            self.assertRaisesRegex(nl_cb_exc.CallbackFailure, "is not a direct binding hostgroup",
                                   self.trunk_plugin.create_trunk, ctx, {'trunk': trunk})

    def test_create_trunk_for_hostgroup_not_found(self):
        with self.port() as trunk_port:
            ctx = context.get_admin_context()
            self._update_vif_type(ctx, trunk_port, host='the-elusive-red-robin')
            trunk = {'port_id': trunk_port['port']['id'],
                     'project_id': 'test_tenant',
                     'sub_ports': []}
            self.assertRaisesRegex(nl_cb_exc.CallbackFailure, "No hostgroup config found for host",
                                   self.trunk_plugin.create_trunk, ctx, {'trunk': trunk})

    def test_create_trunk_for_hostgroup_which_already_has_a_trunk(self):
        with self.port() as trunk_port1:
            ctx = context.get_admin_context()
            self._update_vif_type(ctx, trunk_port1, host='node001-seagull')
            trunk = {'port_id': trunk_port1['port']['id'],
                     'project_id': 'test_tenant',
                     'sub_ports': []}
            resp = self.trunk_plugin.create_trunk(ctx, {'trunk': trunk})
            first_trunk_id = resp['id']
            with self.port() as trunk_port2:
                self._update_vif_type(ctx, trunk_port2, host='node001-seagull')
                trunk = {'port_id': trunk_port2['port']['id'],
                         'project_id': 'test_tenant',
                         'sub_ports': []}
                self.assertRaisesRegex(nl_cb_exc.CallbackFailure,
                                       f"Host node001-seagull already has trunk {first_trunk_id} connected to it",
                                       self.trunk_plugin.create_trunk, ctx, {'trunk': trunk})

    def test_create_trunk_for_hostgroup_which_already_has_a_trunk_but_this_time_it_is_allowed(self):
        with self.port() as trunk_port1:
            ctx = context.get_admin_context()
            self._update_vif_type(ctx, trunk_port1, host='node-multitrunk-seagull')
            trunk = {'port_id': trunk_port1['port']['id'],
                     'project_id': 'test_tenant',
                     'sub_ports': []}
            trunk1 = self.trunk_plugin.create_trunk(ctx, {'trunk': trunk})
            with self.port() as trunk_port2:
                self._update_vif_type(ctx, trunk_port2, host='node-multitrunk-seagull')
                trunk = {'port_id': trunk_port2['port']['id'],
                         'project_id': 'test_tenant',
                         'sub_ports': []}
                trunk2 = self.trunk_plugin.create_trunk(ctx, {'trunk': trunk})
                result = self.mech_driver.fabric_plugin.get_trunks_with_binding_host(ctx, "node-multitrunk-seagull")
                self.assertEqual({trunk1['id'], trunk2['id']}, set(result))

    def test_create_trunk_for_hostgroup_with_subport_that_collides_with_metagroup(self):
        with self.port(device_id='aaa-bbb-ccc') as trunk_port, self.port() as subport:
            ctx = context.get_admin_context()
            self._update_vif_type(ctx, trunk_port, host='node001-seagull')
            sp_dict = {'segmentation_type': 'vlan', 'segmentation_id': 2000, 'port_id': subport['port']['id']}
            trunk = {'port_id': trunk_port['port']['id'],
                     'project_id': 'test_tenant',
                     'sub_ports': [sp_dict]}
            exc_re = "segmentation id 2000 collides with vlan range of switchgroup seagull"
            self.assertRaisesRegex(nl_cb_exc.CallbackFailure, exc_re,
                                   self.trunk_plugin.create_trunk, ctx, {'trunk': trunk})

    def test_create_trunk_for_hostgroup_with_two_subports_in_same_network(self):
        with self.subnet() as subnet:
            with self.port(device_id='aaa-bbb-ccc') as trunk_port, self.port(subnet=subnet) as subport1, \
                    self.port(subnet=subnet) as subport2:
                ctx = context.get_admin_context()
                self._update_vif_type(ctx, trunk_port, host='node001-seagull')
                sp_dict1 = {'segmentation_type': 'vlan', 'segmentation_id': 123, 'port_id': subport1['port']['id']}
                sp_dict2 = {'segmentation_type': 'vlan', 'segmentation_id': 456, 'port_id': subport2['port']['id']}
                trunk = {'port_id': trunk_port['port']['id'],
                         'project_id': 'test_tenant',
                         'sub_ports': [sp_dict1, sp_dict2]}
                exc_re = f"Network {subnet['subnet']['network_id']} cannot be on two subports"
                self.assertRaisesRegex(nl_cb_exc.CallbackFailure, exc_re,
                                       self.trunk_plugin.create_trunk, ctx, {'trunk': trunk})

    def test_create_trunk(self):
        with self.port(device_id='aaa-bbb-ccc') as trunk_port, self.port() as subport:
            ctx = context.get_admin_context()
            self._update_vif_type(ctx, trunk_port, host='node001-seagull')
            sp_dict = {'segmentation_type': 'vlan', 'segmentation_id': 123, 'port_id': subport['port']['id']}
            trunk = {'port_id': trunk_port['port']['id'],
                     'project_id': 'test_tenant',
                     'sub_ports': [sp_dict]}
            resp = self.trunk_plugin.create_trunk(ctx, {'trunk': trunk})
            self.assertEqual('ACTIVE', resp['status'])

            subport_db = self.plugin.get_port(ctx, subport['port']['id'])
            self.assertEqual('node001-seagull', subport_db['binding:host_id'])
            self.assertEqual('trunk:subport', subport_db['device_owner'])
            self.assertEqual(trunk_port['port']['binding:vnic_type'], subport_db['binding:vnic_type'])
            self.assertEqual('aaa-bbb-ccc', subport_db['device_id'])
            self.assertEqual({'segmentation_type': 'vlan', 'segmentation_id': 123, 'trunk_id': resp['id']},
                             subport_db['binding:profile'][cc_const.TRUNK_PROFILE])

    def test_trunk_add_subports_and_remove_subport(self):
        with self.port(device_id='aaa-bbb-ccc') as trunk_port, self.port() as subport:
            ctx = context.get_admin_context()
            self._update_vif_type(ctx, trunk_port, host='node001-seagull')
            trunk = {'port_id': trunk_port['port']['id'],
                     'project_id': 'test_tenant',
                     'sub_ports': []}
            trunk_api = self.trunk_plugin.create_trunk(ctx, {'trunk': trunk})
            self.assertEqual('DOWN', trunk_api['status'])

            # add subport to trunk
            sp_dict = {'segmentation_type': 'vlan', 'segmentation_id': 123, 'port_id': subport['port']['id']}
            self.trunk_plugin.add_subports(ctx, trunk_api['id'], {'sub_ports': [sp_dict]})
            trunk_db = self.trunk_plugin.get_trunk(ctx, trunk_api['id'])
            self.assertEqual("ACTIVE", trunk_db['status'])

            # remove it again
            self.trunk_plugin.remove_subports(ctx, trunk_api['id'],
                                              {'sub_ports': [{'port_id': subport['port']['id']}]})

            trunk_db = self.trunk_plugin.get_trunk(ctx, trunk_api['id'])
            self.assertEqual("DOWN", trunk_db['status'])

    def test_trunk_delete_trunk(self):
        with self.port(device_id='aaa-bbb-ccc') as trunk_port, self.port() as subport:
            ctx = context.get_admin_context()
            self._update_vif_type(ctx, trunk_port, host='node001-seagull')
            trunk = {'port_id': trunk_port['port']['id'],
                     'project_id': 'test_tenant',
                     'sub_ports': []}
            trunk_api = self.trunk_plugin.create_trunk(ctx, {'trunk': trunk})
            self.assertEqual('DOWN', trunk_api['status'])

            # add subport to trunk
            sp_dict = {'segmentation_type': 'vlan', 'segmentation_id': 123, 'port_id': subport['port']['id']}
            self.trunk_plugin.add_subports(ctx, trunk_api['id'], {'sub_ports': [sp_dict]})
            trunk_db = self.trunk_plugin.get_trunk(ctx, trunk_api['id'])
            self.assertEqual("ACTIVE", trunk_db['status'])

            subport_db = self.plugin.get_port(ctx, subport['port']['id'])
            self.assertEqual('node001-seagull', subport_db['binding:host_id'])
            self.assertEqual('aaa-bbb-ccc', subport_db['device_id'])
            self.assertIn(cc_const.TRUNK_PROFILE, subport_db['binding:profile'])

            # remove it again
            self.trunk_plugin.delete_trunk(ctx, trunk_api['id'])

            self.assertRaises(trunk_exc.TrunkNotFound, self.trunk_plugin.get_trunk, ctx, trunk_api['id'])
            subport_db = self.plugin.get_port(ctx, subport['port']['id'])
            self.assertEqual('', subport_db['binding:host_id'])
            self.assertEqual('', subport_db['device_owner'])
            self.assertEqual('', subport_db['device_id'])
            self.assertNotIn(cc_const.TRUNK_PROFILE, subport_db['binding:profile'])

    def test_trunk_add_subport_and_then_a_conflicting(self):
        with self.subnet() as subnet:
            with self.port(device_id='aaa-bbb-ccc') as trunk_port, \
                    self.port(subnet=subnet) as subport1, self.port(subnet=subnet) as subport2:
                ctx = context.get_admin_context()
                self._update_vif_type(ctx, trunk_port, host='node001-seagull')
                trunk = {'port_id': trunk_port['port']['id'],
                         'project_id': 'test_tenant',
                         'sub_ports': []}
                trunk_api = self.trunk_plugin.create_trunk(ctx, {'trunk': trunk})
                self.assertEqual('DOWN', trunk_api['status'])

                # add subport to trunk
                sp_dict = {'segmentation_type': 'vlan', 'segmentation_id': 123, 'port_id': subport1['port']['id']}
                self.trunk_plugin.add_subports(ctx, trunk_api['id'], {'sub_ports': [sp_dict]})
                trunk_db = self.trunk_plugin.get_trunk(ctx, trunk_api['id'])
                self.assertEqual("ACTIVE", trunk_db['status'])

                # add another one with same network, to make sure this fails
                sp_dict = {'segmentation_type': 'vlan', 'segmentation_id': 456, 'port_id': subport2['port']['id']}
                self.assertRaisesRegex(nl_cb_exc.CallbackFailure,
                                       f"Network {subnet['subnet']['network_id']} cannot be on two subports",
                                       self.trunk_plugin.add_subports, ctx, trunk_api['id'], {'sub_ports': [sp_dict]})

    def test_break_transaction(self):
        """This test breaks with the local tests + sqlite, but not with mariadb in prod"""
        self.skipTest("As long as we're testing against sqlite and not mariadb this test won't work")
        ctx1 = context.get_admin_context()
        with self.port(device_id='aaa-bbb-ccc') as trunk_port:
            from neutron_lib.db import api as db_api
            with db_api.CONTEXT_READER.using(ctx1):
                # create trunk
                trunk = trunk_models.Trunk(name='random-trunk1', port_id=trunk_port['port']['id'], sub_ports=[])
                ctx1.session.add(trunk)

                # check if it is there
                print("Before", ctx1.session.query(trunk_models.Trunk).all())

                # get port via extra context
                ctx2 = context.get_admin_context()
                with db_api.CONTEXT_READER.using(ctx2):
                    print(directory.get_plugin().get_ports(ctx2))
                print("Middle ctx2", ctx2.session.query(trunk_models.Trunk).all())

                # check if trunk is still there
                print("After", ctx1.session.query(trunk_models.Trunk).all())
                self.assertEqual(1, len(ctx1.session.query(trunk_models.Trunk).all()))
