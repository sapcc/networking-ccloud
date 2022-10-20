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

from neutron.db.models import address_scope as ascope_models
from neutron.db.models import external_net as extnet_models
from neutron.db.models import segment as segment_models
from neutron.db.models import tag as tag_models
from neutron.db import models_v2
from neutron.services.trunk import models as trunk_models
from neutron.tests.unit.extensions import test_segment
from neutron_lib import context

from networking_ccloud.common.config import _override_driver_config, config_driver
from networking_ccloud.db.db_plugin import CCDbPlugin
from networking_ccloud.tests import base
from networking_ccloud.tests.common import config_fixtures as cfix


class TestDBPluginNetworkSyncData(test_segment.SegmentTestCase, base.PortBindingHelper):
    def setUp(self):
        super().setUp()

        # network a, segments foo bar baz
        #   ports 1(foo), 2(foo), 3-bm(bar)
        #   no port on baz (to make sure this segment is ignored)
        self._net_a = self._make_network(name="a", admin_state_up=True, fmt='json')['network']
        self._subnet_a_1 = self._make_subnet("json", {"network": self._net_a}, "10.180.0.1", "10.180.0.0/24")['subnet']
        self._seg_a = {physnet: self._make_segment(network_id=self._net_a['id'], network_type='vlan',
                       physical_network=physnet, segmentation_id=seg_id, tenant_id='test-tenant',
                       fmt='json')['segment']
                       for physnet, seg_id in (('foo', 100), ('bar', 200), ('baz', 300))}
        self._seg_a[None] = self._make_segment(network_id=self._net_a['id'], network_type='vxlan',
                                               segmentation_id=23232323,
                                               tenant_id="test-tenant", fmt='json')['segment']
        self._port_a_1 = self._make_port_with_binding(segments=[(self._seg_a[None], 'cc-fabric'),
                                                                (self._seg_a['foo'], 'cat-ml2')],
                                                      host='foo-compute')
        self._port_a_2 = self._make_port_with_binding(segments=[(self._seg_a[None], 'cc-fabric'),
                                                                (self._seg_a['foo'], 'seagull-ml2')],
                                                      host='foo-compute')
        self._port_a_3 = self._make_port_with_binding(segments=[(self._seg_a[None], 'cc-fabric'),
                                                                (self._seg_a['bar'], 'penguin-ml2')],
                                                      host='INVALID-BM',
                                                      profile={'local_link_information': [
                                                               {'switch_info': 'bar-baremetal'}]})

        # network b, segments foo spam ham
        #   ports 1(foo) 2(spam) 3(spam) 4(spam) 5-trunk(ham) 6-double(foo,spam)
        self._net_b = self._make_network(name="b", admin_state_up=True, fmt='json')['network']
        self._seg_b = {physnet: self._make_segment(network_id=self._net_b['id'], network_type='vlan',
                       physical_network=physnet, segmentation_id=seg_id, tenant_id='test-tenant',
                       fmt='json')['segment']
                       for physnet, seg_id in (('foo', 400), ('spam', 500), ('ham', 600), ('mew', 700), ('caw', 800))}
        self._seg_b[None] = self._make_segment(network_id=self._net_b['id'], network_type='vxlan',
                                               segmentation_id=42424242,
                                               tenant_id="test-tenant", fmt='json')['segment']
        self._port_b_1 = self._make_port_with_binding(segments=[(self._seg_b[None], 'cc-fabric'),
                                                                (self._seg_b['foo'], 'cat-ml2')],
                                                      host='foo-compute')
        self._port_b_2 = self._make_port_with_binding(segments=[(self._seg_b[None], 'cc-fabric'),
                                                                (self._seg_b['spam'], 'cat-ml2')],
                                                      host='spam-compute')
        self._port_b_3 = self._make_port_with_binding(segments=[(self._seg_b[None], 'cc-fabric'),
                                                                (self._seg_b['spam'], 'cat-ml2')],
                                                      host='spam-compute')
        self._port_b_4 = self._make_port_with_binding(segments=[(self._seg_b[None], 'cc-fabric'),
                                                                (self._seg_b['spam'], 'penguin-ml2')],
                                                      host='node001-spam-compute')
        self._port_b_5 = self._make_port_with_binding(segments=[(self._seg_b[None], 'cc-fabric'),
                                                                (self._seg_b['ham'], 'cat-ml2')],
                                                      host='ham-compute')  # FIXME: trunk
        self._port_b_6a = self._make_port_with_binding(segments=[(self._seg_b[None], 'cc-fabric'),
                                                                 (self._seg_b['mew'], 'cat-ml2')],
                                                       host='mew-compute')
        self._port_b_7b = self._make_port_with_binding(segments=[(self._seg_b[None], 'cc-fabric'),
                                                                 (self._seg_b['caw'], 'cat-ml2')],
                                                       host='caw-compute', port=self._port_b_6a)

        # create trunk
        ctx = context.get_admin_context()
        self._net_c = self._make_network(name="b", admin_state_up=True, fmt='json')['network']
        self._port_c_1 = self._make_port('json', self._net_c['id'])['port']  # bindings don't matter
        with ctx.session.begin():
            subport = trunk_models.SubPort(port_id=self._port_b_5['id'], segmentation_type='vlan', segmentation_id=1000)
            trunk = trunk_models.Trunk(name='random-trunk', port_id=self._port_c_1['id'], sub_ports=[subport])
            ctx.session.add(trunk)

        # network c, external network
        # NOTE: without the l3 plugin we don't have external network support loaded here
        #       therefore we just "cheat" our way into an external network by creating the
        #       appropriate db model
        self._subnetpool_reg = self._make_subnetpool("json", prefixes=["1.1.0.0/16", "2.2.0.0/16"], tenant_id="foo",
                                                     name="sp")['subnetpool']
        self._net_c = self._make_network(name="c", admin_state_up=True, fmt='json')['network']
        with ctx.session.begin():
            ctx.session.add(extnet_models.ExternalNetwork(network_id=self._net_c['id']))

        self._subnet_c_1 = self._make_subnet("json", {"network": self._net_c}, "1.1.1.1", "1.1.1.0/24",
                                             subnetpool_id=self._subnetpool_reg['id'])['subnet']
        self._subnet_c_2 = self._make_subnet("json", {"network": self._net_c}, "2.2.2.2", "2.2.2.0/24",
                                             subnetpool_id=self._subnetpool_reg['id'])['subnet']

        # az aware network
        self._subnetpool_az = self._make_subnetpool("json", prefixes=["1.3.0.0/16"], tenant_id="foo",
                                                    name="sp")['subnetpool']

        self._net_d = self._make_network(name="d", admin_state_up=True, fmt='json')['network']
        with ctx.session.begin():
            net = ctx.session.query(models_v2.Network).get(self._net_d['id'])
            net.availability_zone_hints = '["qa-de-1d"]'
            ctx.session.add(extnet_models.ExternalNetwork(network_id=self._net_d['id']))

            self._address_scope = ascope_models.AddressScope(name="seagull", ip_version=4)
            ctx.session.add(self._address_scope)

            spn_reg = ctx.session.query(models_v2.SubnetPool).get(self._subnetpool_reg['id'])
            spn_reg.address_scope_id = self._address_scope['id']
            spn_az = ctx.session.query(models_v2.SubnetPool).get(self._subnetpool_az['id'])
            spn_az.address_scope_id = self._address_scope['id']
            ctx.session.add(tag_models.Tag(standard_attr_id=spn_az.standard_attr_id,
                                           tag="availability-zone::qa-de-1d"))

        self._subnet_d_1 = self._make_subnet("json", {"network": self._net_d}, "1.3.1.1", "1.3.1.0/24",
                                             subnetpool_id=self._subnetpool_az['id'])['subnet']

        # fix segment index
        with ctx.session.begin():
            objs = ctx.session.query(segment_models.NetworkSegment).filter_by(physical_network=None,
                                                                              network_type='vxlan')
            objs.update({'segment_index': 0})

        # plugin we want to test
        _override_driver_config(123)  # usable config currently not needed by tests
        self._db = CCDbPlugin()

    def _all_hosts(self, net_hosts):
        all_hosts = set()
        for hosts in net_hosts.values():
            all_hosts |= set(hosts)
        return all_hosts

    def test_get_hosts_on_segments_by_segment_ids(self):
        ctx = context.get_admin_context()
        seg_foo = self._seg_a['foo']
        net_hosts = self._db.get_hosts_on_segments(ctx, segment_ids=[seg_foo['id']])
        self.assertEqual(set([seg_foo['id']]), set(v['segment_id'] for e in net_hosts.values() for v in e.values()))

    def test_get_hosts_on_segments_by_network_ids(self):
        ctx = context.get_admin_context()

        # network a
        net_hosts = self._db.get_hosts_on_segments(ctx, network_ids=[self._net_a['id']])
        self.assertEqual(set(["bar-baremetal", "foo-compute"]), self._all_hosts(net_hosts))
        self.assertIn(self._net_a['id'], net_hosts)
        self.assertEqual(100, net_hosts[self._net_a['id']]['foo-compute']['segmentation_id'])

        # network a and b
        net_hosts = self._db.get_hosts_on_segments(ctx, network_ids=[self._net_a['id'], self._net_b['id']])
        self.assertEqual(set(["bar-baremetal", "foo-compute", "spam-compute", "node001-spam-compute", "ham-compute",
                              "mew-compute", "caw-compute"]),
                         self._all_hosts(net_hosts))
        self.assertIn(self._net_a['id'], net_hosts)
        self.assertEqual(400, net_hosts[self._net_b['id']]['foo-compute']['segmentation_id'])

    def test_get_hosts_on_network(self):
        # similar to the first part of test_get_hosts_on_segments_by_network_ids()
        ctx = context.get_admin_context()
        hosts = self._db.get_hosts_on_network(ctx, self._net_a['id'])
        self.assertEqual(set(["bar-baremetal", "foo-compute"]), set(hosts))

    def test_get_hosts_on_segments_by_physnets(self):
        ctx = context.get_admin_context()
        net_hosts = self._db.get_hosts_on_segments(ctx, physical_networks=['foo'])
        self.assertEqual(set([self._net_a['id'], self._net_b['id']]), set(net_hosts))
        self.assertEqual(set(["foo-compute"]), self._all_hosts(net_hosts))

    def test_get_hosts_on_segments_with_driver(self):
        ctx = context.get_admin_context()
        net_hosts = self._db.get_hosts_on_segments(ctx, driver='seagull-ml2')
        self.assertEqual(set(["foo-compute"]), self._all_hosts(net_hosts))

        net_hosts = self._db.get_hosts_on_segments(ctx, driver='penguin-ml2')
        self.assertEqual(set(["node001-spam-compute", "bar-baremetal"]), self._all_hosts(net_hosts))

    def test_get_hosts_on_segments_with_segment_with_wrong_level(self):
        # ...maybe test that the level parameter is working?
        ctx = context.get_admin_context()
        net_hosts = self._db.get_hosts_on_segments(ctx, driver='seagull-ml2', level=0)
        self.assertEqual({}, net_hosts)

    def test_get_hosts_on_segments_with_trunk_ports(self):
        # there should be exactly one trunk port on segment "ham"
        ctx = context.get_admin_context()
        net_hosts = self._db.get_hosts_on_segments(ctx, physical_networks=['ham'])
        self.assertEqual(1, len(net_hosts))
        self.assertEqual(1, len(list(net_hosts.values())[0]))
        self.assertEqual(1000, list(net_hosts.values())[0]['ham-compute']['trunk_segmentation_id'])

    def test_get_top_level_vxlan_segments(self):
        ctx = context.get_admin_context()
        segments = self._db.get_top_level_vxlan_segments(ctx, network_ids=[self._net_a['id']])
        self.assertEqual(1, len(segments))
        for key in ('id', 'network_id', 'network_type', 'segmentation_id', 'physical_network'):
            self.assertEqual(self._seg_a[None][key], getattr(segments[self._net_a['id']], key))

    def test_get_segment_by_host(self):
        ctx = context.get_admin_context()
        segment = self._db.get_segment_by_host(ctx, network_id=self._net_a['id'], physical_network='bar')
        self.assertEqual(self._seg_a['bar']['id'], segment.id)

        segment = self._db.get_segment_by_host(ctx, network_id=self._net_a['id'], physical_network='invalid')
        self.assertIsNone(segment)

    def test_double_portbinding_vlan_mixup(self):
        ctx = context.get_admin_context()
        for i in range(10):
            net_hosts = self._db.get_hosts_on_segments(ctx, network_ids=[self._net_b['id']])
            # make sure we got the right vlan ids and no mixup happened
            self.assertEqual(700, net_hosts[self._net_b['id']]['mew-compute']['segmentation_id'])
            self.assertEqual(800, net_hosts[self._net_b['id']]['caw-compute']['segmentation_id'])

    def test_get_networks_on_physnet(self):
        ctx = context.get_admin_context()
        self.assertEqual({self._net_a['id'], self._net_b['id']}, set(self._db.get_networks_on_physnet(ctx, "foo")))
        self.assertEqual({self._net_b['id']}, set(self._db.get_networks_on_physnet(ctx, "spam")))
        self.assertEqual([], self._db.get_networks_on_physnet(ctx, "invalid_physnet"))

    def test_get_networks_on_physnet_in_use(self):
        ctx = context.get_admin_context()

        # same as above, including in_use
        self.assertEqual({self._net_a['id'], self._net_b['id']},
                         set(self._db.get_networks_on_physnet(ctx, "foo", in_use=True)))

        # with custom segment that has no bindings
        with self.network() as net:
            # I don't know why, but segment() is not a contextmanager.
            self.segment(physical_network="tern", network_id=net['network']['id'], network_type='vlan')
            self.assertEqual([],
                             self._db.get_networks_on_physnet(ctx, "tern", in_use=True))
            self.assertEqual([net['network']['id']],
                             self._db.get_networks_on_physnet(ctx, "tern", in_use=False))

    def test_get_network_ports_on_physnet(self):
        ctx = context.get_admin_context()
        self.assertEqual({self._port_a_1['id'], self._port_a_2['id']},
                         set(self._db.get_network_ports_on_physnet(ctx, self._net_a['id'], "foo")))
        self.assertEqual({self._port_b_1['id']},
                         set(self._db.get_network_ports_on_physnet(ctx, self._net_b['id'], "foo")))
        self.assertEqual({self._port_b_7b['id']},
                         set(self._db.get_network_ports_on_physnet(ctx, self._net_b['id'], "caw")))
        self.assertEqual([], self._db.get_network_ports_on_physnet(ctx, self._net_b['id'], "invalid_physnet"))

    def test_get_gateways_for_networks(self):
        ctx = context.get_admin_context()

        # FIXME: I bet at some point the order of this is going to break and someone will complain about it
        self.assertEqual({self._net_c['id']: [("1.1.1.1/24", "seagull"), ("2.2.2.2/24", "seagull")]},
                         self._db.get_gateways_for_networks(ctx, [self._net_c['id']]))
        self.assertEqual({}, self._db.get_gateways_for_networks(ctx, [self._net_a['id']]))

        # networks without subnetpool/address scope are not returned by this, so....
        self.assertEqual({}, self._db.get_gateways_for_networks(ctx, [self._net_a['id']], external_only=False))

    def test_get_gateways_for_network(self):
        ctx = context.get_admin_context()
        self.assertEqual([("1.1.1.1/24", "seagull"), ("2.2.2.2/24", "seagull")],
                         self._db.get_gateways_for_network(ctx, self._net_c['id']))
        self.assertIsNone(self._db.get_gateways_for_network(ctx, self._net_a['id']))

    def test_get_subnet_l3_config_for_networks(self):
        ctx = context.get_admin_context()
        self.assertEqual({self._subnetpool_reg['id']: [("1.1.1.0/24", None), ("2.2.2.0/24", None)]},
                         self._db.get_subnet_l3_config_for_networks(ctx, [self._net_c['id']]))
        self.assertEqual({self._subnetpool_az['id']: [("1.3.1.0/24", "qa-de-1d")]},
                         self._db.get_subnet_l3_config_for_networks(ctx, [self._net_d['id']]))

    def test_get_subnetpool_details(self):
        ctx = context.get_admin_context()
        self.assertEqual({
            self._subnetpool_reg['id']: {
                'address_scope': 'seagull',
                'az': None,
                'cidrs': ['1.1.0.0/16', '2.2.0.0/16']
            },
            self._subnetpool_az['id']: {
                'address_scope': 'seagull',
                'az': 'qa-de-1d',
                'cidrs': ['1.3.0.0/16']
            }},
            self._db.get_subnetpool_details(ctx, [self._subnetpool_reg['id'], self._subnetpool_az['id']]))


class TestNetworkInterconnectAllocation(test_segment.SegmentTestCase, base.PortBindingHelper):
    def setUp(self):
        super().setUp()

        # create a config with some transits
        switchgroups = [
            cfix.make_switchgroup("seagull", availability_zone="qa-de-1a"),
            cfix.make_switchgroup("cat", availability_zone="qa-de-1b"),
            cfix.make_switchgroup("crow", availability_zone="qa-de-1a"),
        ]

        hostgroups = [
            cfix.make_interconnect(config_driver.HostgroupRole.transit, "transit1", "seagull", ["qa-de-1a"]),
            cfix.make_interconnect(config_driver.HostgroupRole.transit, "transit2", "cat", ["qa-de-1b"]),
            cfix.make_interconnect(config_driver.HostgroupRole.transit, "transit3", "cat", ["qa-de-1b", "qa-de-1c"]),

            cfix.make_interconnect(config_driver.HostgroupRole.bgw, "bgw1", "crow", ["qa-de-1a"]),
        ]
        self.drv_conf = cfix.make_config(switchgroups=switchgroups, hostgroups=hostgroups)
        _override_driver_config(self.drv_conf)

        self._db = CCDbPlugin()

    def test_transit_allocation(self):
        ctx = context.get_admin_context()

        # first network
        net_a = self._make_network(name="a", admin_state_up=True, fmt='json')['network']
        transit_created, transit = self._db.ensure_transit_for_network(ctx, net_a['id'], 'qa-de-1a')
        self.assertTrue(transit_created)
        self.assertEqual("transit1", transit.host)
        self.assertEqual("qa-de-1a", transit.availability_zone)
        self.assertEqual(net_a['id'], transit.network_id)

        # first network, again
        transit_created, transit = self._db.ensure_transit_for_network(ctx, net_a['id'], 'qa-de-1a')
        self.assertFalse(transit_created)
        self.assertEqual("transit1", transit.host)

        # second network
        net_b = self._make_network(name="b", admin_state_up=True, fmt='json')['network']
        transit_created, transit = self._db.ensure_transit_for_network(ctx, net_b['id'], 'qa-de-1a')
        self.assertTrue(transit_created)
        self.assertEqual("transit1", transit.host)

        # third network, only possible on transit3
        net_c = self._make_network(name="c", admin_state_up=True, fmt='json')['network']
        transit_created, transit = self._db.ensure_transit_for_network(ctx, net_c['id'], 'qa-de-1c')
        self.assertTrue(transit_created)
        self.assertEqual("transit3", transit.host)

    def test_same_net_multiple_transits_and_get(self):
        ctx = context.get_admin_context()
        net_a = self._make_network(name="a", admin_state_up=True, fmt='json')['network']

        # qa-de-1a
        transit_created, transit = self._db.ensure_transit_for_network(ctx, net_a['id'], 'qa-de-1a')
        self.assertTrue(transit_created)
        self.assertEqual("transit1", transit.host)

        # qa-de-1c
        transit_created, transit = self._db.ensure_transit_for_network(ctx, net_a['id'], 'qa-de-1c')
        self.assertTrue(transit_created)
        self.assertEqual("transit3", transit.host)

        # qa-de-1b, transit3 should already be bound
        transit_created, transit = self._db.ensure_transit_for_network(ctx, net_a['id'], 'qa-de-1b')
        self.assertFalse(transit_created)
        self.assertEqual("transit3", transit.host)

        # test get
        db_transits = self._db.get_transits_for_network(ctx, net_a['id'])
        self.assertEqual({"transit1", "transit3"}, set(t.host for t in db_transits))
        self.assertEqual({"qa-de-1a", "qa-de-1b", "qa-de-1c"}, set(t.availability_zone for t in db_transits))
        self.assertEqual(3, len(db_transits))

    def test_transit_allocation_with_nonexistant_transit(self):
        ctx = context.get_admin_context()
        net_a = self._make_network(name="a", admin_state_up=True, fmt='json')['network']
        transit_created, transit = self._db.ensure_transit_for_network(ctx, net_a['id'], 'qa-de-1-nonexistant')
        self.assertFalse(transit_created)
        self.assertEqual(None, transit)

    def test_transit_allocation_multiple_transits(self):
        ctx = context.get_admin_context()

        # frist network
        net_a = self._make_network(name="a", admin_state_up=True, fmt='json')['network']
        transit_created, transit = self._db.ensure_transit_for_network(ctx, net_a['id'], 'qa-de-1b')
        self.assertTrue(transit_created)
        self.assertEqual("transit2", transit.host)

        # second network, expect second transit to be allocated
        net_b = self._make_network(name="b", admin_state_up=True, fmt='json')['network']
        transit_created, transit = self._db.ensure_transit_for_network(ctx, net_b['id'], 'qa-de-1b')
        self.assertTrue(transit_created)
        self.assertEqual("transit3", transit.host)

        # third and fourth network, both should be allocated to a different transit
        net_c = self._make_network(name="c", admin_state_up=True, fmt='json')['network']
        net_d = self._make_network(name="d", admin_state_up=True, fmt='json')['network']
        transit_created_3, transit_3 = self._db.ensure_transit_for_network(ctx, net_c['id'], 'qa-de-1b')
        transit_created_4, transit_4 = self._db.ensure_transit_for_network(ctx, net_d['id'], 'qa-de-1b')
        self.assertNotEqual(transit_3.host, transit_4.host, "Transits should not be equal")

    def test_transit_deallocation(self):
        ctx = context.get_admin_context()

        # allocate something we can delete
        net_a = self._make_network(name="a", admin_state_up=True, fmt='json')['network']
        transit_created, transit = self._db.ensure_transit_for_network(ctx, net_a['id'], 'qa-de-1a')
        self.assertTrue(transit_created)

        # remove it
        removed = self._db.remove_transit_from_network(ctx, net_a['id'], 'qa-de-1a')
        self.assertTrue(removed)

        # remove it a second time, should return False
        removed = self._db.remove_transit_from_network(ctx, net_a['id'], 'qa-de-1a')
        self.assertFalse(removed)

    def test_bgw_allocation_deallocation(self):
        # NOTE: we do most tests already with transits, so BGW testing is a bit shorter
        ctx = context.get_admin_context()
        net_a = self._make_network(name="a", admin_state_up=True, fmt='json')['network']

        # test bgw allocation
        bgw_created, bgw = self._db.ensure_bgw_for_network(ctx, net_a['id'], 'qa-de-1a')
        self.assertTrue(bgw_created)
        self.assertEqual("bgw1", bgw.host)

        # make sure we can also still allocate a transit
        transit_created, transit = self._db.ensure_transit_for_network(ctx, net_a['id'], 'qa-de-1a')
        self.assertTrue(transit_created)
        self.assertEqual("transit1", transit.host)
        self.assertEqual("qa-de-1a", transit.availability_zone)
        self.assertEqual(net_a['id'], transit.network_id)

        # same returned second time
        bgw_created_2, bgw_2 = self._db.ensure_bgw_for_network(ctx, net_a['id'], 'qa-de-1a')
        self.assertFalse(bgw_created_2)
        self.assertEqual("bgw1", bgw_2.host)

        # get the bgw from db
        bgws = self._db.get_bgws_for_network(ctx, net_a['id'])
        self.assertEqual(1, len(bgws))
        self.assertEqual("bgw1", bgws[0].host)
        self.assertEqual("qa-de-1a", bgws[0].availability_zone)

        # deallocate
        removed = self._db.remove_bgw_from_network(ctx, net_a['id'], 'qa-de-1a')
        self.assertTrue(removed)

        removed = self._db.remove_bgw_from_network(ctx, net_a['id'], 'qa-de-1a')
        self.assertFalse(removed)
