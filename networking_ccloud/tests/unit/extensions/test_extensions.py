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

from neutron.api import extensions
from neutron.tests.unit.api.test_extensions import setup_extensions_middleware
import webtest

from networking_ccloud.extensions import __path__ as fabric_ext_path
from networking_ccloud.extensions import fabricoperations
from networking_ccloud.tests import base


class TestCustomExtension(base.TestCase):
    def setUp(self):
        super().setUp()
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
