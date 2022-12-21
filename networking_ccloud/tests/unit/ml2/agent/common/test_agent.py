# Copyright 2022 SAP SE
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

from neutron_lib import context
from neutron_lib import rpc as n_rpc
from oslo_config import cfg

from networking_ccloud.common.config import _override_driver_config
from networking_ccloud.ml2.agent.test.agent import CCFabricTestSwitchAgent
from networking_ccloud.tests import base
from networking_ccloud.tests.common import config_fixtures as cfix


class TestAgent(base.TestCase):
    def setUp(self):
        super().setUp()

        switchgroups = [
            cfix.make_switchgroup("seagull", switch_vars={"platform": "test"}, availability_zone="qa-de-1a"),
            cfix.make_switchgroup("tern", switch_vars={"platform": "test"}, availability_zone="qa-de-1a"),

            cfix.make_switchgroup("crow", switch_vars={"platform": "arista-eos"}, availability_zone="qa-de-1a"),
        ]
        self.drv_conf = cfix.make_config(switchgroups=switchgroups, hostgroups=[])
        _override_driver_config(self.drv_conf)

        self.ctx = context.get_admin_context_without_session()

        cfg.CONF.set_override('prometheus_enabled', False, group='ml2_cc_fabric_agent')
        with mock.patch.object(n_rpc, 'get_client'):
            self.agent = CCFabricTestSwitchAgent()
            self.agent.init_host()
            self.agent.after_start()

    def test_switches_initialized(self):
        self.assertEqual({"seagull-sw1", "seagull-sw2", "tern-sw1", "tern-sw2"},
                         {sw.name for sw in self.agent._switches})

    def test_get_syncloop_status(self):
        status = self.agent.get_syncloop_status(self.ctx)
        self.assertEqual({sw.name for sw in self.agent._switches}, set(status['last_sync_time']))
        self.assertTrue(status['enabled'])

    def test_syncloop_status_set_after_full_sync(self):
        for sw in self.agent._switches:
            if sw.name == "seagull-sw1":
                break
        else:
            raise ValueError("Switch not found in tests")

        with mock.patch.object(sw, '_rpc_client'), mock.patch.object(sw, '_apply_config_update') as mock_acu:
            fsf = sw.run_full_sync(self.ctx)
            fsf.result()
            mock_acu.assert_called()

        status = self.agent.get_syncloop_status(self.ctx)
        self.assertIsNotNone(status['last_sync_time']['seagull-sw1'])

    def test_disable_syncloop(self):
        status = self.agent.get_syncloop_status(self.ctx)
        self.assertTrue(status['enabled'])

        self.agent.set_syncloop_enabled(self.ctx, False)

        status = self.agent.get_syncloop_status(self.ctx)
        self.assertFalse(status['enabled'])

        # try running the syncloop and make sure it doesn't do anything
        with mock.patch.object(self.agent, '_switches'):
            self.agent.sync_all_switches(self.ctx)
