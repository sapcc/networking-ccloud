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

from networking_ccloud.common.config import config_driver as config
from networking_ccloud.tests import base


class TestConfigValidation(base.TestCase):
    def make_switch(self, name, host="1.2.3.4", vendor="arista"):
        return config.Switch(name=name, host=host, vendor=vendor, user="admin", password="maunz",
                             bgp_source_ip="2.3.4.5")

    def test_switchgroup_two_members(self):
        sw1 = self.make_switch("sw1")
        sw2 = self.make_switch("sw2")
        sw3 = self.make_switch("sw3")
        sg_args = dict(name="foo", availability_zone="qa-de-1a", role="vpod", vtep_ip="1.1.1.1", asn=65001)

        self.assertRaises(ValueError, config.SwitchGroup, members=[sw1], **sg_args)
        self.assertRaises(ValueError, config.SwitchGroup, members=[sw1, sw2, sw3], **sg_args)
        config.SwitchGroup(members=[sw1, sw2], **sg_args)
