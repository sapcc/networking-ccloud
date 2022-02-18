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
from neutron_lib import constants as nl_const
from neutron_lib.db import api as db_api
from oslo_log import log as logging
import sqlalchemy as sa

from networking_ccloud.common.config import get_driver_config
from networking_ccloud.common import exceptions as cc_exc
from networking_ccloud.common import helper
from networking_ccloud.db import models as cc_models

LOG = logging.getLogger(__name__)


class CCDbPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                 address_scope_db.AddressScopeDbMixin,
                 SegmentDbMixin,
                 external_net_db.External_net_db_mixin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.drv_conf = get_driver_config()

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
                           sa.and_(ml2_models.PortBinding.port_id == ml2_models.PortBindingLevel.port_id,
                                   ml2_models.PortBinding.host == ml2_models.PortBindingLevel.host))
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
        for (port_id, host, profile, segment_id, network_id, segmentation_id, physnet, level, driver,
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

    @db_api.retry_if_session_inactive()
    def get_top_level_vxlan_segments(self, context, network_ids):
        query = context.session.query(segment_models.NetworkSegment)
        query = query.filter_by(network_type=nl_const.TYPE_VXLAN, physical_network=None, segment_index=0)
        query = query.filter(segment_models.NetworkSegment.network_id.in_(network_ids))

        net_seg = {}
        for segment in query.all():
            net_seg[segment.network_id] = segment

        return net_seg

    @db_api.retry_if_session_inactive()
    def get_azs_for_network(self, context, network_id, extra_binding_hosts=None):
        """Get all AZs in this network bound on this driver"""
        # get binding hosts on network
        binding_hosts = self.get_hosts_on_network(context, network_id)
        if extra_binding_hosts:
            binding_hosts += extra_binding_hosts

        azs = set()
        for binding_host in binding_hosts:
            hg_config = self.drv_conf.get_hostgroup_by_host(binding_host)
            if hg_config:
                az = hg_config.get_availability_zone()
                azs.add(az)

        return azs

    @db_api.retry_if_session_inactive()
    def get_transits_for_network(self, context, network_id):
        query = context.session.query(cc_models.CCNetworkTransitMap)
        query = query.filter_by(network_id=network_id)

        return list(query.all())

    @db_api.retry_if_session_inactive()
    def ensure_transit_for_network(self, context, network_id, az):
        """Make sure a network has a transit allocated for an AZ

        Returns a bool indicating if a new transit had to be allocated and the
        DB model itself. If no transit is available, (False, None) is returned.
        Note that false can also be returned when a new DB entry was made, but
        the transit was already allocated to this network, but not the given AZ
        (but also services this AZ).
        """
        with context.session.begin(subtransactions=True):
            query = context.session.query(cc_models.CCNetworkTransitMap)
            query = query.filter_by(network_id=network_id, availability_zone=az)
            if query.count() > 0:
                # Transit already scheduled
                return False, query.all()[0]

            # we need to assign a transit - find candidates from config
            available_transits = [t.binding_host_name for t in self.drv_conf.get_transits_for_az(az)]
            if not available_transits:
                LOG.warning("Can't scheduled transit for network %s - no transit available for AZ %s in config",
                            network_id, az)
                return False, None

            # check that this network has net yet bound one of these transits
            query = context.session.query(cc_models.CCNetworkTransitMap.transit)
            query = query.filter(cc_models.CCNetworkTransitMap.network_id == network_id)
            for entry in query.all():
                if entry[0] in available_transits:
                    # existing transit!
                    new_transit_allocated = False
                    transit = entry[0]
                    break
            else:
                # scheduling algorithm: least used
                new_transit_allocated = True
                query = context.session.query(cc_models.CCNetworkTransitMap.transit,
                                              sa.func.count(cc_models.CCNetworkTransitMap.network_id).label('count'))
                query = query.filter(cc_models.CCNetworkTransitMap.transit.in_(available_transits))
                query = query.group_by(cc_models.CCNetworkTransitMap.transit)
                query = query.order_by('count')

                # check if one transit is not present (not used yet), else use first entry from DB query
                db_transits = [entry[0] for entry in query.all()]
                for transit in available_transits:
                    if transit not in db_transits:
                        break
                else:
                    transit = db_transits[0]

            transit_alloc = cc_models.CCNetworkTransitMap(network_id=network_id, availability_zone=az, transit=transit)
            context.session.add(transit_alloc)

        return new_transit_allocated, transit_alloc

    @db_api.retry_if_session_inactive()
    def remove_transit_from_network(self, context, network_id, az):
        """Remove a transit from a network"""
        query = context.session.query(cc_models.CCNetworkTransitMap)
        query = query.filter(cc_models.CCNetworkTransitMap.network_id == network_id)
        if az is not None:
            query = query.filter(cc_models.CCNetworkTransitMap.availability_zone == az)

        return query.delete() > 0
