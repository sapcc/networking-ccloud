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

from networking_ccloud.common import exceptions as cc_exc
from networking_ccloud.common import helper
from networking_ccloud.tests import base


class TestHelper(base.TestCase):
    def test_get_binding_host_from_profile_working(self):
        profile = {'local_link_information': [{'switch_info': 'foo'}]}
        ret = helper.get_binding_host_from_profile(profile, "$port_id")
        self.assertEqual("foo", ret)

    def test_get_binding_host_from_str_profile_working(self):
        profile = '{"local_link_information": [{"switch_info": "foo"}]}'
        ret = helper.get_binding_host_from_profile(profile, "$port_id")
        self.assertEqual("foo", ret)

    def test_broken_binding_profile_does_not_break_helper(self):
        lli = "local_link_information"
        broken_profiles = [
            None, [], {}, {lli: None}, {lli: []}, {lli: [{}, {}]},
            {lli: [{'foo': 23}]}, "{}", "[",
        ]
        for broken_profile in broken_profiles:
            ret = helper.get_binding_host_from_profile(broken_profile, "$port_id")
            self.assertEqual(None, ret)

    def test_multiple_hosts_in_binding_profile(self):
        broken_profile = {'local_link_information': [{'switch_info': 'foo'}, {'switch_info': 'bar'}]}
        self.assertRaises(cc_exc.MultipleBindingHostsInBindingProfile,
                          helper.get_binding_host_from_profile, broken_profile, "$port_id")

    def test_get_binding_host_from_port_working_profile(self):
        port = {
            'id': '$port_id', 'binding:host_id': 'foo',
            'binding:profile': {'local_link_information': [{'switch_info': 'bar'}]}
        }
        self.assertEqual("bar", helper.get_binding_host_from_port(port))

    def get_binding_host_from_port_empty_profile(self):
        port = {
            'id': '$port_id', 'binding:host_id': 'foo',
        }
        self.assertEqual("foo", helper.get_binding_host_from_port(port))
