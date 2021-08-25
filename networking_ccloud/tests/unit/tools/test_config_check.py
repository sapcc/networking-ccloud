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

from networking_ccloud.tests import base
from networking_ccloud.tools import config_check


class TestConfigValidationTool(base.TestCase):
    def test_failing_without_args(self):
        args = ["cc-config-check"]
        with mock.patch('sys.argv', args):
            self.assertRaises(SystemExit, config_check.main)

    def test_validating_driver_example_config(self):
        args = ["cc-config-check", "-y", "examples/cc-driver-config.yaml"]
        with mock.patch('sys.argv', args):
            config_check.main()
