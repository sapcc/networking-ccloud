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

import ipaddress
import json

from neutron.db import address_scope_db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db.models import address_scope as ascope_models
from neutron.db.models import external_net as extnet_models
from neutron.db.models import segment as segment_models
from neutron.db.models import tag as tag_models
from neutron.db import models_v2
from neutron.plugins.ml2 import models as ml2_models
from neutron.services.segments.db import SegmentDbMixin
from neutron.services.trunk import models as trunk_models
from neutron_lib import constants as nl_const
from neutron_lib.db import api as db_api
from oslo_config import cfg
from oslo_log import log as logging
import sqlalchemy as sa

from networking_ccloud.common.config import get_driver_config
from networking_ccloud.common import constants as cc_const
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
                                sa.and_(trunk_models.SubPort.port_id == ml2_models.PortBinding.port_id,
                                        ml2_models.PortBinding.vif_type == cc_const.VIF_TYPE_CC_FABRIC))

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
                hosts[host] = dict(segment_id=segment_id, network_id=network_id, segmentation_id=segmentation_id,
                                   physical_network=physnet, driver=driver, level=level,
                                   trunk_segmentation_id=trunk_seg_id, is_bgw=False)
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
    def get_segment_by_host(self, context, network_id, physical_network, network_type=nl_const.TYPE_VLAN):
        """Return a single segment defined by network, host and network_type"""
        query = context.session.query(segment_models.NetworkSegment)
        query = query.filter_by(network_id=network_id, physical_network=physical_network, network_type=network_type)
        result = query.all()

        if result:
            return result[0]

        return None

    @db_api.retry_if_session_inactive()
    def get_segments_by_physnet_network_tuples(self, context, physnet_networks, network_type=nl_const.TYPE_VLAN):
        """Get all segments which have one of the given combinations of physnet and network_id"""
        query = context.session.query(segment_models.NetworkSegment)
        query = query.filter_by(network_type=network_type)
        query = query.filter(sa.tuple_(segment_models.NetworkSegment.physical_network,
                                       segment_models.NetworkSegment.network_id).in_(physnet_networks))
        result = {}
        for segment in query.all():
            result[(segment.physical_network, segment.network_id)] = segment
        return result

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
                az = hg_config.get_availability_zone(self.drv_conf)
                azs.add(az)

        return azs

    @db_api.retry_if_session_inactive()
    def get_interconnects(self, context, network_id=None, device_type=None, host=None):
        query = context.session.query(cc_models.CCNetworkInterconnects)
        filter_args = {}
        if network_id:
            filter_args['network_id'] = network_id
        if device_type:
            filter_args['device_type'] = device_type
        if host:
            filter_args['host'] = host
        query = query.filter_by(**filter_args)

        return list(query.all())

    def get_transits_for_network(self, context, network_id):
        return self.get_interconnects(context, network_id, cc_const.DEVICE_TYPE_TRANSIT)

    def get_bgws_for_network(self, context, network_id):
        return self.get_interconnects(context, network_id, cc_const.DEVICE_TYPE_BGW)

    @db_api.retry_if_session_inactive()
    def ensure_interconnect_for_network(self, context, device_type, network_id, az, only_own_az=False):
        """Make sure a network has an interconnect of device_type allocated for an AZ

        Returns a bool indicating if a new interconnect had to be allocated plus the
        DB model itself. If no interconnect is available, (False, None) is returned.
        Note that False can also be returned when a new DB entry was made, but
        the interconnect was already allocated to this network, but not the given AZ
        (but also services this AZ) - this can only happen for Transits as they are
        the only devices servicing a different AZ.
        """
        with context.session.begin(subtransactions=True):
            query = context.session.query(cc_models.CCNetworkInterconnects)
            query = query.filter_by(device_type=device_type, network_id=network_id, availability_zone=az)
            if query.count() > 0:
                # Interconnection device already scheduled
                return False, query.all()[0]

            # we need to assign a device - find candidates from config
            avail_devices = [t.binding_host_name for t in self.drv_conf.get_interconnects_for_az(device_type, az)
                             if not only_own_az or t.get_availability_zone(self.drv_conf) == az]
            if not avail_devices:
                LOG.warning("Can't schedule interconnect %s for network %s - no %s available for AZ %s in config",
                            device_type, network_id, device_type, az)
                return False, None

            # check that this network has not yet bound one of these interconnects
            query = context.session.query(cc_models.CCNetworkInterconnects.host)
            query = query.filter_by(device_type=device_type, network_id=network_id)
            for entry in query.all():
                if entry[0] in avail_devices:
                    # existing transit!
                    new_interconnect_allocated = False
                    host = entry[0]
                    break
            else:
                # scheduling algorithm: least used
                new_interconnect_allocated = True
                query = context.session.query(cc_models.CCNetworkInterconnects.host,
                                              sa.func.count(cc_models.CCNetworkInterconnects.network_id).label('count'))
                query = query.filter_by(device_type=device_type)
                query = query.filter(cc_models.CCNetworkInterconnects.host.in_(avail_devices))
                query = query.group_by(cc_models.CCNetworkInterconnects.host)
                query = query.order_by('count')

                # check if one transit is not present (not used yet), else use first entry from DB query
                db_devices = [entry[0] for entry in query.all()]
                for host in avail_devices:
                    if host not in db_devices:
                        break
                else:
                    host = db_devices[0]

            transit_alloc = cc_models.CCNetworkInterconnects(device_type=device_type, network_id=network_id,
                                                             availability_zone=az, host=host)
            context.session.add(transit_alloc)

        return new_interconnect_allocated, transit_alloc

    def ensure_transit_for_network(self, context, network_id, az):
        return self.ensure_interconnect_for_network(context, cc_const.DEVICE_TYPE_TRANSIT, network_id, az)

    def ensure_bgw_for_network(self, context, network_id, az):
        return self.ensure_interconnect_for_network(context, cc_const.DEVICE_TYPE_BGW, network_id, az)

    @db_api.retry_if_session_inactive()
    def remove_interconnect_from_network(self, context, device_type, network_id, az):
        """Remove a transit from a network"""
        query = context.session.query(cc_models.CCNetworkInterconnects)
        query = query.filter_by(device_type=device_type, network_id=network_id)
        if az is not None:
            query = query.filter_by(availability_zone=az)

        return query.delete() > 0

    def remove_transit_from_network(self, context, network_id, az):
        return self.remove_interconnect_from_network(context, cc_const.DEVICE_TYPE_TRANSIT, network_id, az)

    def remove_bgw_from_network(self, context, network_id, az):
        return self.remove_interconnect_from_network(context, cc_const.DEVICE_TYPE_BGW, network_id, az)

    @db_api.retry_if_session_inactive()
    def get_gateways_for_networks(self, context, network_ids, external_only=True):
        fields = [
            models_v2.Subnet.network_id, models_v2.Subnet.cidr, models_v2.Subnet.gateway_ip,
            ascope_models.AddressScope.name
        ]
        query = context.session.query(*fields)
        query = query.filter(models_v2.Subnet.network_id.in_(network_ids))
        query = query.filter(models_v2.Subnet.cidr.isnot(None))
        query = query.filter(models_v2.Subnet.gateway_ip.isnot(None))
        query = query.join(models_v2.SubnetPool,
                           models_v2.Subnet.subnetpool_id == models_v2.SubnetPool.id)
        query = query.join(ascope_models.AddressScope,
                           models_v2.SubnetPool.address_scope_id == ascope_models.AddressScope.id)

        if external_only:
            query = query.join(extnet_models.ExternalNetwork,
                               models_v2.Subnet.network_id == extnet_models.ExternalNetwork.network_id)

        if not cfg.CONF.ml2_cc_fabric.handle_all_l3_gateways:
            # only handle tagged networks
            query = query.join(models_v2.Network,
                               models_v2.Subnet.network_id == models_v2.Network.id)
            query = query.join(tag_models.Tag,
                               models_v2.Network.standard_attr_id == tag_models.Tag.standard_attr_id)
            query = query.filter(tag_models.Tag.tag == cc_const.L3_GATEWAY_TAG)

        result = {}
        for entry in query.all():
            # we assume that the gateway is always in the network (ensured by openstack)
            # --> we can just piece the gateway together
            suffix = entry.cidr.split("/")[1]
            gw_ip = f"{entry.gateway_ip}/{suffix}"
            result.setdefault(entry.network_id, []).append((gw_ip, entry.name))

        # make sure the results are sorted
        for gws in result.values():
            gws.sort(key=lambda entry: int(ipaddress.ip_interface(entry[0]).ip))

        return result

    def get_gateways_for_network(self, context, network_id, *args, **kwargs):
        net_gws = self.get_gateways_for_networks(context, [network_id], *args, **kwargs)
        return net_gws.get(network_id)

    def get_subnet_l3_config_for_networks(self, context, network_ids):
        """Get l3 config (cidrs, az locality) for networks, grouped by subnet pools"""
        fields = [
            models_v2.Subnet.subnetpool_id, models_v2.Subnet.cidr,
            models_v2.Network.availability_zone_hints,
        ]

        query = context.session.query(*fields)

        # we only get config for external networks, no reason to bother with anything else
        # (until we maybe have DAPNET support, but that's something for the future)
        query = query.join(extnet_models.ExternalNetwork,
                           models_v2.Subnet.network_id == extnet_models.ExternalNetwork.network_id)
        query = query.join(models_v2.Network,
                           models_v2.Subnet.network_id == models_v2.Network.id)
        query = query.filter(models_v2.Subnet.subnetpool_id.isnot(None))

        # FIXME: the number of networks in the request can get quite large. would it maybe make more sense
        #        to pre-filter these for external networks and then do the in_() to reduce query size?
        query = query.filter(models_v2.Subnet.network_id.in_(network_ids))

        # group by subnet pool
        result = {}
        for snp_id, cidr, net_az_hint in query.all():
            az_hint = None
            try:
                if net_az_hint:
                    net_az_hint = json.loads(net_az_hint)
                    if len(net_az_hint) >= 1:
                        az_hint = net_az_hint[0]
            except json.JSONDecodeError:
                # this is just to protect us from botched DB info, normally OpenStack should prevent this
                pass
            result.setdefault(snp_id, []).append((cidr, az_hint))

        return result

    def get_subnetpool_details(self, context, subnetpool_ids):
        # get az from tags
        fields = [models_v2.SubnetPool.id, tag_models.Tag.tag]
        query = context.session.query(*fields)
        query = query.join(tag_models.Tag,
                           models_v2.SubnetPool.standard_attr_id == tag_models.Tag.standard_attr_id)
        query = query.filter(models_v2.SubnetPool.id.in_(subnetpool_ids))
        query = query.filter(tag_models.Tag.tag.like(f'{cc_const.AZ_TAG_PREFIX}%'))

        snp_az = {}
        for snp_id, tag in query.all():
            snp_az[snp_id] = tag[len(cc_const.AZ_TAG_PREFIX):]

        # get the subnet pools
        fields = [
            models_v2.SubnetPool.id, models_v2.SubnetPoolPrefix.cidr,
            ascope_models.AddressScope.name,
        ]
        query = context.session.query(*fields)

        query = query.join(models_v2.SubnetPoolPrefix,
                           models_v2.SubnetPool.id == models_v2.SubnetPoolPrefix.subnetpool_id)
        query = query.join(ascope_models.AddressScope,
                           models_v2.SubnetPool.address_scope_id == ascope_models.AddressScope.id)

        query = query.filter(models_v2.SubnetPool.id.in_(subnetpool_ids))
        query = query.order_by(models_v2.SubnetPool.id, models_v2.SubnetPoolPrefix.cidr)

        # sort pools by address scope
        result = {}
        for snp_id, cidr, ascope_name in query.all():
            if snp_id not in result:
                result[snp_id] = {
                    "cidrs": [],
                    "az": snp_az.get(snp_id),
                    "address_scope": ascope_name,
                }
            result[snp_id]['cidrs'].append(cidr)

        return result

    @db_api.retry_if_session_inactive()
    def get_subport_trunk_vlan_id(self, context, port_id):
        query = context.session.query(trunk_models.SubPort.segmentation_id)
        query = query.filter(trunk_models.SubPort.port_id == port_id)
        subport = query.first()
        if subport:
            return subport.segmentation_id
        return None

    @db_api.retry_if_session_inactive()
    def get_trunks_with_binding_host(self, context, host):
        fields = [
            trunk_models.Trunk.id,
            trunk_models.Trunk.port_id,
            ml2_models.PortBinding.host,
            ml2_models.PortBinding.profile,
        ]
        query = context.session.query(*fields)
        query = query.join(ml2_models.PortBinding,
                           trunk_models.Trunk.port_id == ml2_models.PortBinding.port_id)
        query = query.filter(sa.or_(ml2_models.PortBinding.host == host,
                                    ml2_models.PortBinding.profile.like(f"%{host}%")))

        trunk_ids = []
        for trunk_id, port_id, port_host, port_profile in query.all():
            port_profile_host = helper.get_binding_host_from_profile(port_profile, port_id)
            if port_profile_host:
                port_host = port_profile_host
            if port_host != host:
                continue
            trunk_ids.append(trunk_id)
        return trunk_ids
