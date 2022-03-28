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
from networking_ccloud.common import constants as cc_const
from networking_ccloud.tests import base
from networking_ccloud.tests.common import config_fixtures as cfix


class TestDriverConfigValidation(base.TestCase):
    def make_switch(self, name, host="1.2.3.4", platform=cc_const.PLATFORM_EOS):
        return config.Switch(name=name, host=host, platform=platform, user="admin", password="maunz",
                             bgp_source_ip="2.3.4.5")

    def test_switchgroup_two_members(self):
        sw1 = self.make_switch("sw1")
        sw2 = self.make_switch("sw2")
        sw3 = self.make_switch("sw3")
        sg_args = dict(name="foo", availability_zone="qa-de-1a", role="vpod", vtep_ip="1.1.1.1", asn=65001)

        self.assertRaises(ValueError, config.SwitchGroup, members=[sw1], **sg_args)
        self.assertRaises(ValueError, config.SwitchGroup, members=[sw1, sw2, sw3], **sg_args)
        config.SwitchGroup(members=[sw1, sw2], **sg_args)

    def test_switchport_lacp_attr_validation(self):
        defargs = {'switch': 'sw-seagull', 'name': 'e1/1/1/1'}

        self.assertRaisesRegex(ValueError, ".*LACP members without LACP being enabled",
                               config.SwitchPort, lacp=False, members=["foo"], **defargs)
        self.assertRaisesRegex(ValueError, ".*is LACP port and has no members",
                               config.SwitchPort, lacp=True, **defargs)
        self.assertRaisesRegex(ValueError, ".*is LACP port and has no members",
                               config.SwitchPort, lacp=True, members=[], **defargs)
        self.assertRaisesRegex(ValueError, ".*has a portchannel id set without LACP being enabled",
                               config.SwitchPort, lacp=False, portchannel_id=23, **defargs)

    def test_switchport_pc_id_parsing(self):
        cases = [("Port-Channel23", 23), ("port-channel42", 42), ("port-Channel 1337", 1337)]
        for pc_name, pc_id in cases:
            sp = config.SwitchPort(switch='sw-seagull', name=pc_name, lacp=True, members=["krakrakra"])
            self.assertEqual(pc_id, sp.portchannel_id, f"Could not parse pc id from {pc_name}")

    def test_switchport_pc_id_is_not_overridden(self):
        sp = config.SwitchPort(switch='sw-seagull', name="Port-Channel23", portchannel_id=42, lacp=True,
                               members=["krakrakra"])
        self.assertEqual(42, sp.portchannel_id)

    def test_hostgroup_direct_binding_mode_default(self):
        hg = config.Hostgroup(metagroup=True, binding_hosts=["foo"], members=["foo"])
        self.assertEqual(False, hg.direct_binding)

        hg = config.Hostgroup(metagroup=True, binding_hosts=["foo"], members=["foo"], direct_binding=True)
        self.assertEqual(True, hg.direct_binding)

        hg = config.Hostgroup(binding_hosts=["foo"], members=[config.SwitchPort(switch="sw-cat", name="e1/1/1")])
        self.assertEqual(True, hg.direct_binding)

        hg = config.Hostgroup(binding_hosts=["foo"], members=[config.SwitchPort(switch="sw-cat", name="e1/1/1")],
                              direct_binding=False)
        self.assertEqual(False, hg.direct_binding)

    def test_cannot_bind_iface_multiple_times(self):
        gc = cfix.make_global_config()
        sg = cfix.make_switchgroup("seagull")
        hg1 = config.Hostgroup(binding_hosts=["foo"], members=[config.SwitchPort(switch="seagull-sw1", name="e1/1/1")])
        hg2 = config.Hostgroup(binding_hosts=["bar"], members=[config.SwitchPort(switch="seagull-sw1", name="e1/1/1")])

        self.assertRaisesRegex(ValueError, ".*Iface seagull-sw1/e1/1/1 is bound two times.*bar.*foo.*",
                               config.DriverConfig, global_config=gc, switchgroups=[sg], hostgroups=[hg1, hg2])

    def test_hostgroup_transit_always_services_own_az(self):
        # should work
        gc = cfix.make_global_config()
        sg = cfix.make_switchgroup("seagull", availability_zone="qa-de-1a")
        hg = config.Hostgroup(role="transit", handle_availability_zones=["qa-de-1a"], binding_hosts=["transit1"],
                              members=[config.SwitchPort(switch="seagull-sw1", name="e1/1/1")])
        config.DriverConfig(global_config=gc, switchgroups=[sg], hostgroups=[hg])

        # should break
        hg = config.Hostgroup(role="transit", handle_availability_zones=["qa-de-1b"], binding_hosts=["transit1"],
                              members=[config.SwitchPort(switch="seagull-sw1", name="e1/1/1")])

        self.assertRaisesRegex(ValueError, "Hostgroup transit1 is in AZ qa-de-1a, but.*",
                               config.DriverConfig, global_config=gc, switchgroups=[sg], hostgroups=[hg])

    def test_hostgroup_bgw_require_unnamed_ifaces(self):
        # normal hg with unnamed interface forbidden
        self.assertRaisesRegex(ValueError, ".*Hostgroup ..bgw1.. with role bgw cannot have named switchports.*",
                               config.Hostgroup, binding_hosts=["bgw1"],
                               role="bgw", handle_availability_zones=["qa-de-1a"],
                               members=[config.SwitchPort(switch="seagull-sw1", name="e1/1/1")])

    def test_hostgroup_require_named_ifaces(self):
        # normal hg with unnamed interface forbidden
        self.assertRaisesRegex(ValueError, ".*Hostgroup ..seagull-compute.. needs to have names for each switchport.*",
                               config.Hostgroup, binding_hosts=["seagull-compute"],
                               members=[config.SwitchPort(switch="seagull-sw1")])


class TestDriverUtilityFunctions(base.TestCase):
    def test_get_hostgroup_by_host(self):
        # FIXME: implement
        pass
