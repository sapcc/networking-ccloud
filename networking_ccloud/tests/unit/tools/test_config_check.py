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

import tempfile
from unittest import mock

import yaml

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

    def test_validation_with_credentials_file(self):
        drv_conf = yaml.safe_load(open("examples/cc-driver-config.yaml"))
        for sg in drv_conf['switchgroups']:
            for sw in sg['members']:
                del sw['user']
                del sw['password']

        creds_conf = {
            "switch_credentials": {
                "qa-de-3-sw1111a-bb206": {"user": "cat", "password": "meow"},
                "qa-de-3-sw1111b-bb206": {"user": "cat", "password": "meow"},
            },
        }

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as conf_file, \
                tempfile.NamedTemporaryFile(mode="w", delete=False) as creds_file:
            conf_file.write(yaml.dump(drv_conf))
            conf_file.close()
            creds_file.write(yaml.dump(creds_conf))
            creds_file.close()

            args = ["cc-config-check", "-y", conf_file.name, "--credentials-file", creds_file.name]
            with mock.patch('sys.argv', args):
                config_check.main()
