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

from neutron.db import address_scope_db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db.models import segment as segment_models
from neutron.plugins.ml2 import models as ml2_models
from neutron.services.segments.db import SegmentDbMixin
from neutron.services.trunk import models as trunk_models
from neutron_lib.db import api as db_api
from oslo_log import log as logging

from networking_ccloud.common import exceptions as cc_exc
from networking_ccloud.common import helper

LOG = logging.getLogger(__name__)


class DbPlugin(db_base_plugin_v2.NeutronDbPluginV2,
               address_scope_db.AddressScopeDbMixin,
               SegmentDbMixin,
               external_net_db.External_net_db_mixin):
    @db_api.retry_if_session_inactive()
    def get_hosts_on_segments(self, context, segment_ids=None, network_ids=None, physical_networks=None, level=1,
                              driver=None):
        """Get all binding hosts plus their segment info

        Find all bound ports and their network segments in the DB.
        This query can be filtered with the following paramerets:
         * segment_ids - only regard these networksegments
         * network_ids - only regard networksegments from these networks
         * physical_networks - only regard networksegments with these physical networks
         * level - only regard bindings on this binding level
         * driver - only regard bindings done by this driver
        The binding host is taken from the port with get_binding_host_from_profile().
        """
        # FIXME: think about if segmenthostmappings could reduce complexity or are just a data-copying-nightmare
        # FIXME: add trunkports directly here? would be convenient, but requires the tables to be present
        fields = [
            ml2_models.PortBinding.port_id, ml2_models.PortBinding.host, ml2_models.PortBinding.profile,
            segment_models.NetworkSegment.id, segment_models.NetworkSegment.network_id,
            segment_models.NetworkSegment.segmentation_id,
            segment_models.NetworkSegment.physical_network,
            ml2_models.PortBindingLevel.level, ml2_models.PortBindingLevel.driver,
            trunk_models.SubPort.segmentation_id,
        ]
        query = context.session.query(*fields)
        query = query.join(ml2_models.PortBindingLevel,
                           ml2_models.PortBinding.port_id == ml2_models.PortBindingLevel.port_id)
        query = query.join(segment_models.NetworkSegment,
                           ml2_models.PortBindingLevel.segment_id == segment_models.NetworkSegment.id)
        query = query.outerjoin(trunk_models.SubPort,
                                trunk_models.SubPort.port_id == ml2_models.PortBinding.port_id)
        if level is not None:
            query = query.filter(ml2_models.PortBindingLevel.level == level)
        if driver is not None:
            query = query.filter(ml2_models.PortBindingLevel.driver == driver)
        if segment_ids is not None:
            query = query.filter(segment_models.NetworkSegment.id.in_(segment_ids))
        if network_ids is not None:
            query = query.filter(segment_models.NetworkSegment.network_id.in_(network_ids))
        if physical_networks is not None:
            query = query.filter(segment_models.NetworkSegment.physical_network.in_(physical_networks))

        net_hosts = {}
        for (port_id, host, profile, segment_id, network_id, segmentation_id, physnet, driver, level,
                trunk_seg_id) in query.all():
            try:
                host = helper.get_binding_host_from_profile(profile, port_id) or host
            except cc_exc.MultipleBindingHostsInBindingProfile as e:
                LOG.error("Ignoring port for sync data request: %s", e)
                continue

            hosts = net_hosts.setdefault(network_id, {})
            if host not in hosts:
                # FIXME: do we want to take the trunk segmentation id from the SubPort table
                #        or alternatively from the port's binding profile?
                hosts[host] = dict(segment_id=segment_id, network_id=network_id, segmentation_id=segmentation_id,
                                   physical_network=physnet, driver=driver, level=level,
                                   trunk_segmentation_id=trunk_seg_id)
            else:
                if hosts[host]['segment_id'] != segment_id:
                    LOG.error("Host %s found on two segments! seg1 %s net1 %s seg2 %s net2 %s",
                              host, hosts[host]['segment_id'], hosts[host]['network_id'], segment_id, network_id)
                if hosts[host]['trunk_segmentation_id'] != trunk_seg_id:
                    LOG.error("Host %s trunk ids differ! id1 %s id2 %s",
                              host, hosts[host]['trunk_segmentation_id'], trunk_seg_id)

        return net_hosts

    def get_hosts_on_network(self, context, network_id):
        """Shortcut to get_hosts_on_segments() returning data for a single network, unpacked"""
        net_hosts = self.get_hosts_on_segments(context, network_ids=[network_id])
        if not net_hosts:
            return []
        return net_hosts[network_id]
