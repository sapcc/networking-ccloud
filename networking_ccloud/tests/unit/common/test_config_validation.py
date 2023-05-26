# Copyright 2021 SAP SE
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_config import cfg

from networking_ccloud.common.config import _override_driver_config
from networking_ccloud.common.config import validate_ml2_vlan_ranges
from networking_ccloud.common import exceptions as cc_exc
from networking_ccloud.tests import base
from networking_ccloud.tests.common import config_fixtures as cfix


class TestConfigValidation(base.TestCase):
    def setUp(self):
        cfg.CONF.set_override('driver_config_path', 'invalid/path/to/conf.yaml', group='ml2_cc_fabric')
        self.conf_drv = cfix.make_config(switchgroups=[cfix.make_switchgroup("seagull"), cfix.make_switchgroup("cat")])
        _override_driver_config(self.conf_drv)
        super().setUp()

    def test_validate_ml2_vlan_ranges_success(self):
        #cfg.CONF.set_override('tenant_network_types', ['vxlan', 'vlan'], group='ml2')
        cfg.CONF.set_override('network_vlan_ranges', ['seagull:23:42', 'cat:53:1337'], group='ml2_type_vlan')
        cfg.CONF.set_override('driver_config_path', 'invalid/path/to/conf.yaml', group='ml2_cc_fabric')
        validate_ml2_vlan_ranges(self.conf_drv)

    def test_validate_ml2_vlan_ranges_failure(self):
        #cfg.CONF.set_override('tenant_network_types', ['vxlan', 'vlan'], group='ml2')
        cfg.CONF.set_override('network_vlan_ranges', ['cat:53:1337'], group='ml2_type_vlan')
        cfg.CONF.set_override('driver_config_path', 'invalid/path/to/conf.yaml', group='ml2_cc_fabric')
        self.assertRaisesRegex(cc_exc.MissingPhysnetsInNeutronConfig, ".*seagull.*",
                               validate_ml2_vlan_ranges, self.conf_drv)
