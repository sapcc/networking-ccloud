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

from neutron.tests.unit.plugins.ml2._test_mech_agent import FakePortContext
from neutron.tests.unit.plugins.ml2 import test_plugin
from neutron_lib.plugins import directory
from oslo_config import cfg

from networking_ccloud.common.config import _override_driver_config
from networking_ccloud.common.config import config_oslo  # noqa, make sure config opts are there
from networking_ccloud.common import constants as c_const


class TestCCFabricMechanismDriver(test_plugin.Ml2PluginV2TestCase):
    _mechanism_drivers = [c_const.CC_DRIVER_NAME]

    def setUp(self):
        cfg.CONF.set_override('driver_config_path', 'invalid/path/to/conf.yaml', group='ml2_cc_fabric')
        _override_driver_config(123)  # FIXME proper fake config
        super().setUp()
        mm = directory.get_plugin().mechanism_manager
        self.mech_driver = mm.mech_drivers[c_const.CC_DRIVER_NAME].obj

    def _test_bind_port(self, fake_segments, fake_host='host'):
        with mock.patch.object(FakePortContext, 'host', new=fake_host):
            # FIXME: maybe use own FakePortContext that is easier to use
            fake_port_context = FakePortContext(None, None, fake_segments)
            fake_port_context.continue_binding = mock.Mock()
            fake_port_context.set_binding = mock.Mock()
            self.mech_driver.bind_port(fake_port_context)
        return fake_port_context

    def test_bind_port(self):
        # FIXME: implement
        pass

    def test_bind_port_host_not_found(self):
        fake_segments = [{'network_type': 'vxlan',
                          'physical_network': None,
                          'segmentation_id': 23,
                          'id': 'test-id'}]
        context = self._test_bind_port(fake_segments, fake_host='unkown_host')
        context.continue_binding.assert_not_called()
        context.set_binding.assert_not_called()
