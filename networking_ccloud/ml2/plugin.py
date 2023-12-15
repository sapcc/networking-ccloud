# Copyright 2022 SAP SE
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
from itertools import groupby
from operator import itemgetter

from neutron_lib.api.definitions import availability_zone as az_api
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib import constants as nl_const
from neutron_lib.plugins import directory
from neutron_lib.plugins.ml2 import api as ml2_api
from oslo_log import log as logging

from networking_ccloud.common import constants as cc_const
from networking_ccloud.common.helper import merge_segment_dicts
from networking_ccloud.db.db_plugin import CCDbPlugin
from networking_ccloud.ml2.agent.common import messages as agent_msg


LOG = logging.getLogger(__name__)


class FabricPlugin(CCDbPlugin):
    def __init__(self):
        super().__init__()

        self._plugin_property = None

    @property
    def _plugin(self):
        if self._plugin_property is None:
            self._plugin_property = directory.get_plugin()
        return self._plugin_property

    def allocate_and_configure_interconnects(self, context, network):
        """Allocate and configure interconnects for a network

        Returns two bools (new_allocation, error)
        """
        errors_found = False
        new_allocation = False

        # find top level segment
        network_id = network['id']
        top_segments = self.get_top_level_vxlan_segments(context, network_ids=[network_id])
        if network_id not in top_segments:
            LOG.error("Network %s has no top level segment (vxlan / physnet None), aborting transit/BGW scheduling",
                      network_id)
            return False, False

        # allocate network interconnects (BGWs / Transits)
        az_hints = network.get(az_api.AZ_HINTS, [])
        created_transits = []
        scul = agent_msg.SwitchConfigUpdateList(agent_msg.OperationEnum.add, self.drv_conf)

        net_azs = az_hints or self.drv_conf.list_availability_zones()
        for az in net_azs:
            for device_type in (cc_const.DEVICE_TYPE_BGW, cc_const.DEVICE_TYPE_TRANSIT):
                if device_type == cc_const.DEVICE_TYPE_BGW and az_hints:
                    # we don't allocate BGWs for AZ-local networks
                    continue

                device_created, device = self.ensure_interconnect_for_network(context, device_type,
                                                                              network_id, az,
                                                                              only_own_az=bool(az_hints))
                if not device_created:
                    # no config needed, already allocated
                    continue

                # new device allocated, create a segment and add the host to scul
                device_hg = self.drv_conf.get_hostgroup_by_host(device.host)
                if not device_hg:
                    LOG.error("Could not bind device type %s host %s in network %s: Host not found in config",
                              device_type, device.host, network_id)
                    errors_found = True
                    continue

                device_physnet = device_hg.get_vlan_pool_name(self.drv_conf)
                segment_spec = {
                    ml2_api.NETWORK_TYPE: nl_const.TYPE_VLAN,
                    ml2_api.PHYSICAL_NETWORK: device_physnet,
                }
                device_segment = self._plugin.type_manager.allocate_dynamic_segment(context, network_id,
                                                                                    segment_spec)
                device_segment['is_bgw'] = device_type == cc_const.DEVICE_TYPE_BGW
                device_segment['trunk_segmentation_id'] = None
                self.add_segments_to_config(context, scul, {network_id: {device.host: device_segment}})

                if device_type == cc_const.DEVICE_TYPE_TRANSIT:
                    # add to notify list later on
                    created_transits.append((az, device.host, device_segment['id'], device_physnet))

                LOG.info("Allocated device %s to %s for network %s in az %s on vlan %s",
                         device_type, device.host, network_id, az, device_segment[ml2_api.SEGMENTATION_ID])
                new_allocation = True

        if new_allocation and not scul.execute(context, synchronous=False):
            LOG.warning("Scheduling network interconnects for network %s yielded no config updates", network_id)

        for az, host, segment_id, physnet in created_transits:
            # notify others
            LOG.debug("Sending out notify for transit creation on %s for host %s az %s segment %s",
                      network_id, host, az, segment_id)
            payload_metadata = {
                'network_id': network_id,
                'availability_zone': az,
                'host': host,
                'segment_id': segment_id,
                'physical_network': physnet,
            }
            payload = events.DBEventPayload(context, metadata=payload_metadata)
            registry.publish(cc_const.CC_TRANSIT, events.AFTER_CREATE, self, payload=payload)

        return new_allocation, errors_found

    def get_gateways_with_vrfs_for_networks(self, context, network_ids, *args, **kwargs):
        net_gws = self.get_gateways_for_networks(context, network_ids, *args, **kwargs)
        result = {}
        for network_id, gws in net_gws.items():
            result[network_id] = net = {'vrf': None, 'ips': []}
            for gw_ip, ascope in gws:
                vrf = self.drv_conf.global_config.get_vrf_name_for_address_scope(ascope)
                if not vrf:
                    LOG.warning("Address scope %s has no matching VRF for network %s", ascope, network_id)
                    continue
                if net['vrf'] is None:
                    net['vrf'] = vrf
                if net['vrf'] != vrf:
                    # "this should never happen"
                    LOG.error("Network address scope misconfiguration: Network %s has networks in two VRFs: (%s, %s), "
                              "therefore we are skipping l3 config of this network entirely",
                              network_id, result[network_id]['vrf'], vrf)
                    del result[network_id]
                    break
                net['ips'].append(gw_ip)
            if network_id in result and not net['ips']:
                del result[network_id]

        return result

    def get_gateways_with_vrfs_for_network(self, context, network_id, *args, **kwargs):
        net_gws = self.get_gateways_with_vrfs_for_networks(context, [network_id], *args, **kwargs)
        return net_gws.get(network_id)

    def add_segments_to_config(self, context, scul, net_segments):
        top_segments = self.get_top_level_vxlan_segments(context, network_ids=list(net_segments))
        net_gateways = self.get_gateways_with_vrfs_for_networks(context, list(net_segments), external_only=True)

        l3_net_switch_map = {}
        for network_id, segments in net_segments.items():
            if network_id not in top_segments:
                # FIXME: maybe don't use a value error
                raise ValueError(f"Network id {network_id} is missing its top level vxlan segment")

            segment_0 = top_segments[network_id]
            vni = segment_0['segmentation_id']

            for binding_host, segment_1 in segments.items():
                vlan = segment_1['segmentation_id']
                hg_config = self.drv_conf.get_hostgroup_by_host(binding_host)
                if not hg_config:
                    LOG.error("Got a port binding for binding host %s in network %s, which was not found in config",
                              binding_host, network_id)
                    continue
                trunk_vlan = segment_1['trunk_segmentation_id']
                # FIXME: exclude_hosts
                # FIXME: direct binding hosts? are they included?
                gateways = net_gateways.get(network_id)
                scul.add_binding_host_to_config(hg_config, network_id, vni, vlan, trunk_vlan,
                                                gateways=gateways, is_bgw=segment_1['is_bgw'])
                if gateways:
                    l3_net_switch_map.setdefault(network_id, set()).update(hg_config.get_switch_names(self.drv_conf))

        # group switches if they have the same set of l3 networks on them
        # (same set means same l3 query ==> less queries)
        switch_nets = [(sorted(switch_names), network_id) for network_id, switch_names in l3_net_switch_map.items()]
        switch_nets.sort()
        for switch_names, switch_networks in groupby(switch_nets, key=itemgetter(0)):
            network_ids = [network_id for _, network_id in switch_networks]
            vrf_config = self.get_l3_network_config(context, network_ids)
            for vrf_name, vrf in vrf_config.items():
                scul.add_vrf_bgp_config(switch_names, vrf_name,
                                        vrf['vrf_networks'], vrf['vrf_aggregates'])

    def make_switchgroup_config(self, context, sg):
        scul = agent_msg.SwitchConfigUpdateList(agent_msg.OperationEnum.replace, self.drv_conf)

        # physnets of this switch, which is the switch's switchgroup's vlan pool
        physnets = [sg.vlan_pool]

        # get all binding hosts bound onto that switch
        net_segments = self.get_hosts_on_segments(context, physical_networks=physnets)

        # add interconnects, infra networks and extra vlans
        for hg in self.drv_conf.get_hostgroups_by_switches([sw.name for sw in sg.members]):
            if hg.infra_networks:
                scul.add_infra_networks_from_hostgroup(hg, sg)
            if hg.extra_vlans:
                scul.add_extra_vlans(hg)
            if hg.role:
                # transits/BGWs don't have bindings, so bind all physnets
                # find all physnets or interconnects scheduled
                # we normally only have one interconnect per switch, so we can just make the call here
                interconnect_segments = self.get_interconnects_segments(context, host=hg.binding_hosts[0])
                merge_segment_dicts(net_segments, interconnect_segments)

        self.add_segments_to_config(context, scul, net_segments)

        return scul

    def make_switch_config(self, context, switch, sg):
        scul = self.make_switchgroup_config(context, sg)
        scul.clean_switches([switch.name])
        return scul

    def make_network_config(self, context, network_id):
        scul = agent_msg.SwitchConfigUpdateList(agent_msg.OperationEnum.add, self.drv_conf)

        # FIXME: do we need to query this here a second time? the only difference is that we LOG an error
        #        and add_segments_to_config() raises an exception. Hm.
        top_segments = self.get_top_level_vxlan_segments(context, network_ids=[network_id])
        if network_id not in top_segments:
            LOG.error("Network %s has no top level segment (vxlan / physnet None), cannot create network config",
                      network_id)
            return None

        # network segments
        net_segments = self.get_hosts_on_segments(context, network_ids=[network_id])
        interconnect_segments = self.get_interconnects_segments(context, network_id=network_id)
        merge_segment_dicts(net_segments, interconnect_segments)
        self.add_segments_to_config(context, scul, net_segments)

        return scul

    def get_interconnects_segments(self, context, **kwargs):
        """Works similar as get_hosts_on_segments(), only for interconnects without portbindings"""
        devices = self.get_interconnects(context, **kwargs)
        physnet_network_devices = {}
        for device in devices:
            device_hg = self.drv_conf.get_hostgroup_by_host(device.host)
            if not device_hg:
                LOG.error("Could not bind device type %s host %s in network %s: Host not found in config",
                          device.device_type, device.host, device.network_id)
                continue
            device_physnet = device_hg.get_vlan_pool_name(self.drv_conf)
            physnet_network_devices[(device_physnet, device.network_id)] = device

        db_segments = self.get_segments_by_physnet_network_tuples(context, set(physnet_network_devices.keys()))

        net_segments = {}
        for physnet_network, device in physnet_network_devices.items():
            device_segment = db_segments.get(physnet_network)
            if device_segment is None:
                LOG.error("Missing network segment for interconnect %s physnet %s in network %s",
                          device.host, device_physnet, device.network_id)
                continue

            hosts = net_segments.setdefault(device.network_id, {})
            hosts[device.host] = dict(segment_id=device_segment['id'], network_id=device.network_id,
                                      segmentation_id=device_segment[ml2_api.SEGMENTATION_ID],
                                      physical_network=device_segment[ml2_api.PHYSICAL_NETWORK],
                                      driver=None, level=None, trunk_segmentation_id=None,
                                      is_bgw=device.device_type == cc_const.DEVICE_TYPE_BGW)

        return net_segments

    def get_l3_network_config(self, context, network_ids):
        if len(network_ids) == 0:
            return {}

        subnetpool_cidrs = self.get_subnet_l3_config_for_networks(context, network_ids)
        subnetpools = self.get_subnetpool_details(context, list(subnetpool_cidrs))

        # sort subnet pools into vrfs
        # note, that we are iterating over subnetpools and therefore only consider networks that
        # have a valid address scope (as everything else will be omitted by the DB query)
        vrfs = {}
        for snp_id, snp_data in subnetpools.items():
            vrf = self.drv_conf.global_config.get_vrf_name_for_address_scope(snp_data['address_scope'])
            if not vrf:
                LOG.warning("Address scope %s of subnet pool %s has no matching VRF in driver config, skipping it",
                            snp_data['address_scope'], snp_id)
                continue

            vrf = vrfs.setdefault(vrf, {"subnet_cidrs": set(), "subnetpool_cidrs": set()})
            vrf['subnetpool_cidrs'].update((cidr, snp_data['az']) for cidr in snp_data['cidrs'])
            vrf['subnet_cidrs'].update(subnetpool_cidrs[snp_id])

        # sort to network and aggregates
        for vrf in vrfs.values():
            vrf['vrf_aggregates'] = []

            # networks
            # every subnet cidr gets announced
            #   az locality comes from network
            #   externally announcable if there is a matching subnetpool cidr
            subnetpool_cidrs = [cidr for cidr, _ in vrf['subnetpool_cidrs']]
            vrf_networks = []
            for subnet_cidr, az_data in vrf['subnet_cidrs']:
                # cidr has to exist in list of subnetpool-cidrs (all subnet pools of this vrf)
                az_local = bool(az_data)
                ext_announcable = subnet_cidr in subnetpool_cidrs
                vrf_networks.append((subnet_cidr, az_local, ext_announcable))
            vrf['vrf_networks'] = vrf_networks

            # aggregates
            # subnetpool cidrs get announced if they aren't already announced as network via ext_announcable
            #   az locality comes from subnetpool tag
            subnet_cidrs = [cidr for cidr, _ in vrf['subnet_cidrs']]
            vrf_aggregates = []
            for snp_cidr, snp_az_local in vrf['subnetpool_cidrs']:
                if snp_cidr in subnet_cidrs:
                    continue
                vrf_aggregates.append((snp_cidr, bool(snp_az_local)))
            vrf['vrf_aggregates'] = vrf_aggregates

            vrf['vrf_networks'].sort(key=lambda entry: ipaddress.ip_interface(entry[0]).ip)
            vrf['vrf_aggregates'].sort(key=lambda entry: ipaddress.ip_interface(entry[0]).ip)

        return vrfs
