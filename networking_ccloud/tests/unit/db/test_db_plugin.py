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

from neutron.services.trunk import models as trunk_models
from neutron.tests.unit.extensions import test_segment
from neutron_lib import context

from networking_ccloud.db.db_plugin import CCDbPlugin
from networking_ccloud.tests import base


class TestDBPluginNetworkSyncData(test_segment.SegmentTestCase, base.PortBindingHelper):
    def setUp(self):
        super().setUp()

        # network a, segments foo bar baz
        #   ports 1(foo), 2(foo), 3-bm(bar)
        #   no port on baz (to make sure this segment is ignored)
        self._net_a = self._make_network(name="a", admin_state_up=True, fmt='json')['network']
        self._seg_a = {physnet: self._make_segment(network_id=self._net_a['id'], network_type='vlan',
                       physical_network=physnet, segmentation_id=seg_id, tenant_id='test-tenant',
                       fmt='json')['segment']
                       for physnet, seg_id in (('foo', 100), ('bar', 200), ('baz', 300))}
        self._seg_a[None] = self._make_segment(network_id=self._net_a['id'], network_type='vxlan',
                                               physical_network='', segmentation_id=23232323,
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
        #   ports 1(foo) 2(spam) 3(spam) 4(spam) 5-trunk(ham)
        self._net_b = self._make_network(name="b", admin_state_up=True, fmt='json')['network']
        self._seg_b = {physnet: self._make_segment(network_id=self._net_b['id'], network_type='vlan',
                       physical_network=physnet, segmentation_id=seg_id, tenant_id='test-tenant',
                       fmt='json')['segment']
                       for physnet, seg_id in (('foo', 400), ('spam', 500), ('ham', 600))}
        self._seg_b[None] = self._make_segment(network_id=self._net_b['id'], network_type='vxlan',
                                               physical_network='', segmentation_id=42424242,
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

        # create trunk
        ctx = context.get_admin_context()
        self._net_c = self._make_network(name="b", admin_state_up=True, fmt='json')['network']
        self._port_c_1 = self._make_port('json', self._net_c['id'])['port']  # bindings don't matter
        with ctx.session.begin():
            subport = trunk_models.SubPort(port_id=self._port_b_5['id'], segmentation_type='vlan', segmentation_id=1000)
            trunk = trunk_models.Trunk(name='random-trunk', port_id=self._port_c_1['id'], sub_ports=[subport])
            ctx.session.add(trunk)

        # plugin we want to test
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
        print(net_hosts)
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
        self.assertEqual(set(["bar-baremetal", "foo-compute", "spam-compute", "node001-spam-compute", "ham-compute"]),
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
