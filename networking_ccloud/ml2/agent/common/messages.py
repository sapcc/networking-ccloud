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

from enum import Enum
import ipaddress
from operator import attrgetter
import re
from typing import List, Optional, Set, Union

from neutron_lib.plugins.ml2 import api as ml2_api
from oslo_log import log as logging
import pydantic

import networking_ccloud.common.config.config_driver as dcfg
from networking_ccloud.common.config.config_driver import validate_asn, ensure_host_bit_set, ensure_network
from networking_ccloud.common import constants as cc_const
from networking_ccloud.ml2.agent.common.api import CCFabricSwitchAgentRPCClient

LOG = logging.getLogger(__name__)


def validate_route_target(rt) -> str:
    # https://datatracker.ietf.org/doc/html/rfc4360#section-4
    # https://datatracker.ietf.org/doc/html/rfc4364#section-4.2
    if not isinstance(rt, str):
        rt = str(rt)

    if rt.isdecimal():
        rt = int(rt)
        if (rt >> 48) & 0xFF != 0x2:
            raise ValueError("Route targets are extended attributes and need to have a 0x2 in the type field's "
                             f"low order position - {rt} does not have this set (RFC 4360 sec 4)")
        rt_type = rt >> 56
        # 8byte rt
        if rt_type == 0:
            # 2 byte asn, 4byte admin field
            a = (rt >> 32) & (2**16 - 1)
            b = rt & (2**32 - 1)
            rt = f"{a}:{b}"
        elif rt_type == 1:
            # 4 byte ip, 2byte admin field
            a = (rt >> 16) & (2**32 - 1)
            b = rt & (2**16 - 1)
            rt = f"{ipaddress.ip_address(a)}:{b}"
        elif rt_type == 2:
            # 4 byte asn, 2byte admin field
            a = (rt >> 16) & (2**32 - 1)
            b = rt & (2**16 - 1)
            if a > 2**16:
                rt = f"{a >> 16}.{a & (2**16 - 1)}:{b}"
            else:
                rt = f"{a}:{b}"
        else:
            raise ValueError(f"Rt {rt} has invalid type {rt_type}, see RFC 4364 sec 4.2")
    else:
        # ip:num, asn:num, num:num
        m = re.match(r"^(?P<first>(?:\d+\.\d+\.\d+\.\d+)|(?:\d+\.\d+)|(?:\d+)):(?P<second>\d+)$", rt)
        if not m:
            raise ValueError(f"RT '{rt}' is not in a recognizable format")
        # automatically reformat cases where ASN is > 16bit to AS dot notation
        first = m.group('first')
        if first.isdecimal() and int(first) >= 2**16:
            first = int(first)
            rt = f"{first >> 16}.{first & (2**16 - 1)}:{m.group('second')}"
    return rt

class OperationEnum(str, Enum):
    add = 'add'
    remove = 'remove'
    replace = 'replace'


class Vlan(pydantic.BaseModel):
    vlan: pydantic.conint(gt=0, lt=4094)
    name: str = None


class VXLANMapping(pydantic.BaseModel):
    vni: pydantic.conint(gt=0, lt=2**24)
    vlan: pydantic.conint(gt=0, lt=4094)


class VRFVXLANMapping(pydantic.BaseModel):
    vrf: str
    vni: pydantic.conint(gt=0, lt=2**24)


class BGPVlan(pydantic.BaseModel):
    # FIXME: validator
    rd: str
    rd_evpn_domain_all: bool = False
    vlan: pydantic.conint(gt=0, lt=4094)

    rt_imports: List[str] = []
    rt_exports: List[str] = []
    rt_imports_evpn: List[str] = []
    rt_exports_evpn: List[str] = []

    _norm_rt_imports = pydantic.validator('rt_imports', each_item=True, allow_reuse=True)(validate_route_target)
    _norm_rt_exports = pydantic.validator('rt_exports', each_item=True, allow_reuse=True)(validate_route_target)
    _norm_rt_imports_evpn = pydantic.validator('rt_imports_evpn',
                                               each_item=True, allow_reuse=True)(validate_route_target)
    _norm_rt_exports_evpn = pydantic.validator('rt_exports_evpn',
                                               each_item=True, allow_reuse=True)(validate_route_target)


class BGPVRFAggregate(pydantic.BaseModel):
    network: str
    route_map: str

    _ensure_network = pydantic.validator('network', each_item=True, allow_reuse=True)(ensure_network)

    def __hash__(self) -> int:
        return hash(self.network)

    def __lt__(self, other) -> bool:
        return other.network < self.network


class BGPVRFNetwork(pydantic.BaseModel):
    network: str
    route_map: str

    _ensure_host_bit_set = pydantic.validator('network', each_item=True, allow_reuse=True)(ensure_host_bit_set)

    def __hash__(self) -> int:
        return hash(self.network)

    def __lt__(self, other) -> bool:
        return other.network < self.network


class BGPVRF(pydantic.BaseModel):
    # FIXME: validator
    rd: str
    name: str
    rt_imports: Optional[List[str]] = None
    rt_exports: Optional[List[str]] = None

    aggregates: Optional[Set[BGPVRFAggregate]] = None
    networks: Optional[Set[BGPVRFNetwork]] = None

    _norm_rt_imports = pydantic.validator('rt_imports', each_item=True, allow_reuse=True)(validate_route_target)
    _norm_rt_exports = pydantic.validator('rt_exports', each_item=True, allow_reuse=True)(validate_route_target)

    def add_default_rts(self, asn_region: str, vrf_number: int,
                        local_az: dcfg.AvailabilityZone, all_azs: List[dcfg.AvailabilityZone]):
        if not self.rt_imports:
            self.rt_imports = list()
        for az in all_azs:
            self.rt_imports.append(f"{asn_region}:{az.number}{vrf_number}")

        if not self.rt_exports:
            self.rt_exports = list()
        self.rt_exports.append(f"{asn_region}:{local_az.number}{vrf_number}")

class BGP(pydantic.BaseModel):
    asn: str
    asn_region: str

    vlans: List[BGPVlan] = None
    vrfs: List[BGPVRF] = None

    _normalize_asn = pydantic.validator('asn', allow_reuse=True)(validate_asn)
    _normalize_asn_region = pydantic.validator('asn_region', allow_reuse=True)(validate_asn)

    def add_vlan(self, vlan, vni, bgw_mode=False):
        # FIXME: raise if vni > 2byte (can't encode it in RT otherwise, write snarky commit message for that)
        if not self.vlans:
            self.vlans = []

        rd = f"{self.asn}:{vni}"
        for bv in self.vlans:
            if bv.rd == rd and bv.vlan == vlan:
                return

        rt = f"{self.asn_region}:{vni}"
        bvargs = dict(rt_imports=[rt], rt_exports=[rt])
        if bgw_mode:
            bvargs['rd_evpn_domain_all'] = True
            bvargs['rt_imports_evpn'] = [rt]
            bvargs['rt_exports_evpn'] = [rt]

        self.vlans.append(BGPVlan(rd=rd, vlan=vlan, **bvargs))

    def get_or_create_vrf(self, name: str, vrf_number: str) -> BGPVRF:
        if not self.vrfs:
            self.vrfs = []

        for vrf in self.vrfs:
            if vrf.name == name:
                return vrf

        rd = f"{self.asn}:{vrf_number}"
        vrf = BGPVRF(name=name, rd=rd)
        self.vrfs.append(vrf)
        return vrf


class VlanTranslation(pydantic.BaseModel):
    inside: pydantic.conint(gt=0, lt=4094)
    outside: pydantic.conint(gt=0, lt=4094)


class IfaceConfig(pydantic.BaseModel):
    name: str

    vrf: str = None
    ip_addresses: List[str] = None
    description: str = None

    native_vlan: pydantic.conint(gt=0, lt=4094) = None
    trunk_vlans: List[pydantic.conint(gt=0, lt=4094)] = None
    vlan_translations: List[VlanTranslation] = None
    portchannel_id: pydantic.conint(gt=0) = None
    members: List[str] = None

    @classmethod
    def from_switchport(cls, switchport):
        iface = cls(name=switchport.name)
        if switchport.lacp:
            iface.portchannel_id = switchport.portchannel_id
            iface.members = switchport.members
        return iface

    def add_trunk_vlan(self, vlan):
        if not self.trunk_vlans:
            self.trunk_vlans = []
        if vlan not in self.trunk_vlans:
            self.trunk_vlans.append(vlan)

    def add_vlan_translation(self, inside, outside):
        if not self.vlan_translations:
            self.vlan_translations = []
        for vt in self.vlan_translations:
            if vt.inside == inside and vt.outside == outside:
                return
        self.vlan_translations.append(VlanTranslation(inside=inside, outside=outside))


class RouteMap(pydantic.BaseModel):
    name: str
    set_rts: List[str] = None

    _norm_set_rts = pydantic.validator('set_rts', each_item=True, allow_reuse=True)(validate_route_target)

    @staticmethod
    def gen_name(name, prefix="RM", az_suffix=None, aggregate=False):
        rm = [prefix, name]
        if az_suffix:
            rm.append(az_suffix.upper())
        if aggregate:
            rm.append("AGGREGATE")
        return "-".join(rm)


class VRF(pydantic.BaseModel):
    name: str
    ip_routing: bool = True


class SwitchConfigUpdate(pydantic.BaseModel):
    switch_name: str
    operation: OperationEnum

    vlans: List[Vlan] = None
    vrfs: List[VRF] = None
    route_maps: List[RouteMap] = None
    vxlan_maps: List[VXLANMapping] = None
    vrf_vxlan_maps: List[VXLANMapping] = None
    bgp: BGP = None
    ifaces: List[IfaceConfig] = None  # noqa: E701 (pyflakes bug)

    @classmethod
    def make_object_from_net_data(self, vxlan_map, net_host_map):
        pass

    def dict(self, *args, **kwargs):
        # in case we want to compare this or ship it to the user we may benefit from it being sorted
        # also test cases would fail otherwise
        if self.vlans:
            self.vlans.sort(key=attrgetter('vlan'))
        if self.vxlan_maps:
            self.vxlan_maps.sort(key=attrgetter('vlan'))
        if self.ifaces:
            self.ifaces.sort(key=attrgetter('name'))
        return super().dict(*args, **kwargs)

    def add_vlan(self, vlan, name=None):
        if self.vlans is None:
            self.vlans = []
        for v in self.vlans:
            if v.vlan == vlan:
                return
        self.vlans.append(Vlan(vlan=vlan, name=name))

    def add_vxlan_map(self, vni, vlan):
        if self.vxlan_maps is None:
            self.vxlan_maps = []
        for vm in self.vxlan_maps:
            if vm.vni == vni and vm.vlan == vlan:
                return
        self.vxlan_maps.append(VXLANMapping(vni=vni, vlan=vlan))

    def add_vrf_vxlan_map(self, vrf, vni):
        if self.vrf_vxlan_maps is None:
            self.vrf_vxlan_maps = []
        for vm in self.vrf_vxlan_maps:
            if vm.vrf == vrf and vm.vni == vni:
                return
        self.vrf_vxlan_maps.append(VRFVXLANMapping(vrf=vrf, vni=vni))

    def add_iface(self, iface):
        if self.ifaces is None:
            self.ifaces = []
        self.ifaces.append(iface)

        return iface

    def get_iface(self, name):
        if self.ifaces is None:
            self.ifaces = []

        for iface in self.ifaces:
            if iface.name == name:
                return iface
        return None

    def get_or_create_iface(self, name):
        iface = self.get_iface(name)
        if iface:
            return iface

        iface = IfaceConfig(name=name)
        self.ifaces.append(iface)
        return iface

    def get_or_create_iface_from_switchport(self, switchport):
        iface = self.get_iface(switchport.name)
        if iface:
            return iface

        iface = IfaceConfig.from_switchport(switchport)
        self.ifaces.append(iface)
        return iface

    def add_vrf(self, name, ip_routing):
        if not self.vrfs:
            self.vrfs = []

        for vrf in self.vrfs:
            if vrf.name == name:
                return
        self.vrfs.append(VRF(name=name, ip_routing=ip_routing))

    def add_route_map(self, name, **kwargs):
        if not self.route_maps:
            self.route_maps = []

        for rm in self.route_maps:
            if rm.name == name:
                return
        self.route_maps.append(RouteMap(name=name, **kwargs))


class SwitchConfigUpdateList:
    def __init__(self, operation: OperationEnum, drv_conf: dcfg.DriverConfig):
        self.operation = operation
        self.drv_conf = drv_conf
        self.switch_config_updates = {}

    def get_or_create_switch(self, switch_name) -> SwitchConfigUpdate:
        if switch_name not in self.switch_config_updates:
            self.switch_config_updates[switch_name] = SwitchConfigUpdate(switch_name=switch_name,
                                                                         operation=self.operation)
        return self.switch_config_updates[switch_name]

    def add_binding_host_from_segment_to_config(self, binding_host, *args, **kwargs):
        # find binding host
        hg_config = self.drv_conf.get_hostgroup_by_host(binding_host)
        if hg_config is None:
            # FIXME: maybe don't use a value error here
            raise ValueError(f"Could not find binding host {binding_host}")

        return self.add_binding_host_to_config(hg_config, *args, **kwargs)

    def add_binding_host_to_config(self, hg_config, network_name, vni, vlan, trunk_vlan=None,
                                   keep_mapping=False, exclude_hosts=None, is_bgw=False):
        """Add binding host config to all required switches

        Given a hostgroup config this method generates and adds config to this
        config request. "Add" means that the config will be added, the overall
        operation (add, remove, replace) is determined by self.operation.

        Params:
         * keep_mapping: determines if the vlan-vni mapping is kept on op=remove/replace
         * exclude_hosts: hosts to exclude if a metagroup is being bound
         * is_bgw: bordergateway mode - no ifaces will be configured, bgp stanzas marked as bgw
        """
        add = self.operation == OperationEnum.add
        for switch_name, switchports in hg_config.iter_switchports(self.drv_conf, exclude_hosts=exclude_hosts):
            switch = self.drv_conf.get_switch_by_name(switch_name)
            scu = self.get_or_create_switch(switch.name)

            # add bgp stuff
            if vni and (add or not keep_mapping):
                if not scu.bgp:
                    sg = self.drv_conf.get_switchgroup_by_switch_name(switch.name)
                    scu.bgp = BGP(asn=sg.asn, asn_region=self.drv_conf.global_config.asn_region)
                scu.bgp.add_vlan(vlan, vni, bgw_mode=is_bgw)

            # vlan-vxlan mapping
            if vni and (add or not keep_mapping):
                scu.add_vlan(vlan, network_name)
                scu.add_vxlan_map(vni, vlan)

            # interface config
            if not is_bgw:
                for sp in switchports:
                    iface = scu.get_or_create_iface_from_switchport(sp)
                    iface.add_trunk_vlan(vlan)

                    if hg_config.direct_binding and not hg_config.role:
                        if trunk_vlan:
                            iface.add_vlan_translation(vlan, trunk_vlan)
                        else:
                            iface.native_vlan = vlan

    def add_segments(self, net_segments, top_segments):
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
                # FIXME: handle trunk_vlans
                # FIXME: exclude_hosts
                # FIXME: direct binding hosts? are they included?
                self.add_binding_host_to_config(hg_config, network_id, vni, vlan)

    def add_interconnects(self, context, fabric_plugin, interconnects):
        network_ids = set(ic.network_id for ic in interconnects)
        top_segments = fabric_plugin.get_top_level_vxlan_segments(context, network_ids=network_ids)
        for device in interconnects:
            if device.network_id not in top_segments:
                # this is an error and not an exception, because the method is used by the switch sync
                # and I didn't want that a broken network could prevent the sync of a while switch
                LOG.error("Could not create config for interconnect of network %s: Missing top segment",
                          device.network_id)
                continue
            vni = top_segments[device.network_id]['segmentation_id']

            device_hg = self.drv_conf.get_hostgroup_by_host(device.host)
            if not device_hg:
                LOG.error("Could not bind device type %s host %s in network %s: Host not found in config",
                          device.device_type, device.host, device.network_id)
                continue

            device_physnet = device_hg.get_vlan_pool_name(self.drv_conf)
            device_segment = fabric_plugin.get_segment_by_host(context, device.network_id, device_physnet)
            if not device_segment:
                LOG.error("Missing network segment for interconnect %s physnet %s in network %s",
                          device.host, device_physnet, device.network_id)
                continue

            self.add_binding_host_to_config(device_hg, device.network_id, vni, device_segment[ml2_api.SEGMENTATION_ID],
                                            is_bgw=device.device_type == cc_const.DEVICE_TYPE_BGW)

    def _get_switch_bgp_l3_attributes(self, switch: dcfg.Switch, vrf: Union[str, dcfg.VRF]):  # type: ignore
        sg: dcfg.SwitchGroup = self.drv_conf.get_switchgroup_by_switch_name(switch.name)  # type: ignore
        az: dcfg.AvailabilityZone = self.drv_conf.get_availability_zone(sg.availability_zone)  # type: ignore

        if isinstance(vrf, str):
            vrf_name = vrf
            vrf: dcfg.VRF = self.drv_conf.get_vrf(vrf_name)  # type: ignore
            if not vrf:
                # FIXME: should this be an exception? should this be a ValueError?
                raise ValueError(f"No vrf found for VRF name '{vrf_name}'")

        return dict(vrf=vrf, az=az, asn=sg.asn)

    def add_vrf(self, hg_config: dcfg.Hostgroup, vrf: Union[dcfg.VRF, str],  # type: ignore
                exclude_hosts: Optional[str] = None):

        asn_region = self.drv_conf.global_config.asn_region
        for switch_name, switchports in hg_config.iter_switchports(self.drv_conf, exclude_hosts=exclude_hosts):
            switch: dcfg.Switch = self.drv_conf.get_switch_by_name(switch_name)  # type: ignore
            scu = self.get_or_create_switch(switch.name)

            bgp_l3_attribs = self._get_switch_bgp_l3_attributes(switch, vrf)
            asn = bgp_l3_attribs['asn']
            vrf: dcfg.VRF = bgp_l3_attribs['vrf']  # type: ignore
            az: dcfg.AvailabilityZone = bgp_l3_attribs['az']  # type: ignore

            # ip vrf / vrf instance
            scu.add_vrf(vrf.name, ip_routing=True)

            # route maps
            scu.add_route_map(name=RouteMap.gen_name(vrf.name), set_rts=[f"{asn_region}:{vrf.number}"])
            scu.add_route_map(name=RouteMap.gen_name(vrf.name, aggregate=True),
                              set_rts=[f"{asn_region}:{vrf.number}", f"{asn_region}:1"])
            scu.add_route_map(name=RouteMap.gen_name(vrf.name, az_suffix=az.suffix),
                              set_rts=[f"{asn_region}:{az.number}{vrf.number}"])
            scu.add_route_map(name=RouteMap.gen_name(vrf.name, az_suffix=az.suffix, aggregate=True),
                              set_rts=[f"{asn_region}:{az.number}{vrf.number}", f"{asn_region}:1"])

            # BGP base configuration to propagate VRF routes into EVPN
            if not scu.bgp:
                scu.bgp = BGP(asn=asn, asn_region=asn_region)

            bgpvrf = scu.bgp.get_or_create_vrf(vrf.name, vrf.number)
            bgpvrf.add_default_rts(asn_region, vrf.number, az, self.drv_conf.global_config.availability_zones)

    def add_l3_networks_in_vrf(self, hg_config: dcfg.Hostgroup, vrf: Union[dcfg.VRF, str], network_name: str,
                               vni: int, vlan: int, networks: List[str], aggregates: List[str], az_local: bool,
                               exclude_hosts=None):

        # FIXME: Due to the summarization we do, we cannot singularly just add a network or an aggregation, as this
        #        could break existing networks on the device. I see 2 options here:
        #        1. We implement anything working with networks and aggregates as a replace only method and assume that
        #           this will only ever get called with all necessary networks. However as the configured networks
        #           differ from switchgroup to switchgroup, we need to pass a switchgroup -> vrf -> present_networks
        #           mapping as an argument to this function too.
        #        2. We decide that we do the aggregation on the switch-class level, meaning we obtain a configuration
        #           lock, read the current configured networks on that device and then build aggregates as well
        #           as network statements

        asn_region = self.drv_conf.global_config.asn_region

        for switch_name, switchports in hg_config.iter_switchports(self.drv_conf, exclude_hosts=exclude_hosts):
            switch: dcfg.Switch = self.drv_conf.get_switch_by_name(switch_name)  # type: ignore
            scu = self.get_or_create_switch(switch.name)

            bgp_l3_attribs = self._get_switch_bgp_l3_attributes(switch, vrf)
            vrf: dcfg.VRF = bgp_l3_attribs['vrf']  # type: ignore
            az: dcfg.AvailabilityZone = bgp_l3_attribs['az']  # type: ignore
            asn = bgp_l3_attribs['asn']

            # bgp vrf
            # advertise network via BGP
            if not scu.bgp:
                scu.bgp = BGP(asn=asn, asn_region=asn_region)

            bgpvrf = scu.bgp.get_or_create_vrf(vrf.name, vrf.number)

            # build aggregates and networks + their route maps
            rm_args = {'name': vrf.name}
            if az_local:
                rm_args['az_suffix'] = az.suffix

            for aggr in aggregates:
                bgpvrf_aggregate = BGPVRFAggregate(network=str(ipaddress.ip_network(aggr, strict=False)),
                                                   route_map=RouteMap.gen_name(aggregate=True, **rm_args))
                if not bgpvrf.aggregates:
                    bgpvrf.aggregates = set()
                bgpvrf.aggregates.add(bgpvrf_aggregate)

            for net in networks:
                aggregate = any(ipaddress.ip_network(aggr, strict=False) == ipaddress.ip_network(net, strict=False)
                                for aggr in aggregates)
                bgpvrf_net = BGPVRFNetwork(network=net, route_map=RouteMap.gen_name(aggregate=aggregate, **rm_args))
                if not bgpvrf.networks:
                    bgpvrf.networks = set()
                bgpvrf.networks.add(bgpvrf_net)

            # associate VRF
            scu.add_vrf_vxlan_map(vrf.name, vni)

            # anycast gateway interface
            viface = IfaceConfig(name=f"vlan{vlan}", description=network_name, vrf=vrf.name, ip_addresses=networks)
            scu.add_iface(viface)

    def execute(self, context, synchronous=True):
        platform_updates = {}
        for scu in self.switch_config_updates.values():
            platform = self.drv_conf.get_switch_by_name(scu.switch_name).platform
            platform_updates.setdefault(platform, []).append(scu)

        if not platform_updates:
            return False

        for platform, updates in platform_updates.items():
            rpc_client = CCFabricSwitchAgentRPCClient.get_for_platform(platform)
            rpc_client.apply_config_update(context, updates, synchronous=synchronous)

        return True
