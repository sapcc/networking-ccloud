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
import re
from typing import List

from oslo_log import log as logging
import pydantic

from networking_ccloud.common.config.config_driver import validate_asn
from networking_ccloud.ml2.agent.common.api import CCFabricSwitchAgentRPCClient

LOG = logging.getLogger(__name__)


def validate_route_target(rt):
    if str(rt).isdecimal() and (int(rt) >> 48) & 0xFF != 0x2:
        raise ValueError("Route targets are extended attributes and need to have a 0x2 in the type field's "
                         f"low order position - {rt} does not have this set (RFC 4360 sec 4)")
    return validate_route_distinguisher(rt)


def validate_route_distinguisher(rdrt) -> str:
    # https://datatracker.ietf.org/doc/html/rfc4360#section-4
    # https://datatracker.ietf.org/doc/html/rfc4364#section-4.2
    if not isinstance(rdrt, str):
        rdrt = str(rdrt)

    if rdrt.isdecimal():
        rdrt = int(rdrt)
        rdrt_type = rdrt >> 56
        # 8byte rdrt
        if rdrt_type == 0:
            # 2 byte asn, 4byte admin field
            a = (rdrt >> 32) & (2**16 - 1)
            b = rdrt & (2**32 - 1)
            rdrt = f"{a}:{b}"
        elif rdrt_type == 1:
            # 4 byte ip, 2byte admin field
            a = (rdrt >> 16) & (2**32 - 1)
            b = rdrt & (2**16 - 1)
            rdrt = f"{ipaddress.ip_address(a)}:{b}"
        elif rdrt_type == 2:
            # 4 byte asn, 2byte admin field
            a = (rdrt >> 16) & (2**32 - 1)
            b = rdrt & (2**16 - 1)
            if a > 2**16:
                rdrt = f"{a >> 16}.{a & (2**16 - 1)}:{b}"
            else:
                rdrt = f"{a}:{b}"
        else:
            raise ValueError(f"RD/RT {rdrt} has invalid type {rdrt_type}, see RFC 4364 sec 4.2")
    else:
        # ip:num, asn:num, num:num
        m = re.match(r"^(?P<first>(?:\d+\.\d+\.\d+\.\d+)|(?:\d+\.\d+)|(?:\d+)):(?P<second>\d+)$", rdrt)
        if not m:
            raise ValueError(f"RD/RT '{rdrt}' is not in a recognizable format")
        # automatically reformat cases where ASN is > 16bit to AS dot notation
        first = m.group('first')
        if first.isdecimal() and int(first) >= 2**16:
            first = int(first)
            rdrt = f"{first >> 16}.{first & (2**16 - 1)}:{m.group('second')}"
    return rdrt


def ensure_network(net):
    # raises ValueError if host bits are set
    net = ipaddress.ip_network(net, strict=True)
    return str(net)


class OperationEnum(str, Enum):
    add = 'add'
    remove = 'remove'
    replace = 'replace'


class Vlan(pydantic.BaseModel):
    vlan: pydantic.conint(gt=0, lt=4094)
    name: str = None

    def __lt__(self, other):
        return self.vlan < other.vlan


class VXLANMapping(pydantic.BaseModel):
    # FIXME: medidate over if we really need this as a separate config object
    #        could the VNI just be part of the vlan and that's that?
    vni: pydantic.conint(gt=0, lt=2**24)
    vlan: pydantic.conint(gt=0, lt=4094)

    def __lt__(self, other):
        return self.vlan < other.vlan


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

    def __lt__(self, other):
        return self.vlan < other.vlan


class BGPVRFNetwork(pydantic.BaseModel):
    network: str
    az_local: bool
    ext_announcable: bool

    _ensure_network = pydantic.validator('network', allow_reuse=True)(ensure_network)


class BGPVRFAggregate(pydantic.BaseModel):
    network: str
    az_local: bool

    _ensure_network = pydantic.validator('network', allow_reuse=True)(ensure_network)


class BGPVRF(pydantic.BaseModel):
    name: str
    networks: List[BGPVRFNetwork] = None
    aggregates: List[BGPVRFAggregate] = None

    def __lt__(self, other):
        return self.name < other.name

    def add_networks(self, networks):
        if not self.networks:
            self.networks = []
        self.networks.extend(networks)

    def add_aggregates(self, aggregates):
        if not self.aggregates:
            self.aggregates = []
        self.aggregates.extend(aggregates)


class BGP(pydantic.BaseModel):
    asn: str
    asn_region: str

    # the switchgroup id is only used for putting together RDs
    # it will not be filled when config is pulled from the device
    switchgroup_id: int = None

    vlans: List[BGPVlan] = None
    vrfs: List[BGPVRF] = None

    _normalize_asn = pydantic.validator('asn', allow_reuse=True)(validate_asn)
    _normalize_asn_region = pydantic.validator('asn_region', allow_reuse=True)(validate_asn)

    def sort(self):
        if self.vlans:
            self.vlans.sort()
        if self.vrfs:
            self.vrfs.sort()

    def add_vlan(self, vlan, vni, az_num, bgw_mode=False):
        # FIXME: raise if vni > 2byte (can't encode it in RT otherwise, write snarky commit message for that)
        if not self.vlans:
            self.vlans = []

        if self.switchgroup_id is None:
            raise Exception("add_vlan() is only available when switchgroup_id is set (programming error)")

        rd = f"{self.switchgroup_id}:{vni}"
        for bv in self.vlans:
            if bv.rd == rd and bv.vlan == vlan:
                return

        rt = f"{az_num}:{vni}"
        bvargs = dict(rt_imports=[rt], rt_exports=[rt])
        if bgw_mode:
            bgw_rt = f"{self.asn_region}:{vni}"
            bvargs['rd_evpn_domain_all'] = True
            bvargs['rt_imports_evpn'] = [bgw_rt]
            bvargs['rt_exports_evpn'] = [bgw_rt]

        self.vlans.append(BGPVlan(rd=rd, vlan=vlan, **bvargs))

    def get_or_create_vrf(self, name: str) -> BGPVRF:
        if not self.vrfs:
            self.vrfs = []

        for vrf in self.vrfs:
            if vrf.name == name:
                return vrf

        vrf = BGPVRF(name=name)
        self.vrfs.append(vrf)
        return vrf


class VlanTranslation(pydantic.BaseModel):
    inside: pydantic.conint(gt=0, lt=4094)
    outside: pydantic.conint(gt=0, lt=4094)


class IfaceConfig(pydantic.BaseModel):
    name: str
    description: str = None

    native_vlan: pydantic.conint(gt=0, lt=4094) = None
    trunk_vlans: List[pydantic.conint(gt=0, lt=4094)] = None
    vlan_translations: List[VlanTranslation] = None
    portchannel_id: pydantic.conint(gt=0) = None
    members: List[str] = None
    speed: str = None

    def __lt__(self, other):
        return self.name < other.name

    def sort(self):
        if self.members:
            self.members.sort()
        if self.trunk_vlans:
            self.trunk_vlans.sort(key=lambda x: int(str(x).split("..")[0]))
        if self.vlan_translations:
            self.vlan_translations.sort()

    @classmethod
    def from_switchport(cls, switchport):
        iface = cls(name=switchport.name, speed=switchport.speed)
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


class VlanIface(pydantic.BaseModel):
    vlan: pydantic.conint(gt=0, lt=4094)
    vrf: str = None

    primary_ip: str = None
    secondary_ips: List[str] = None

    def __lt__(self, other):
        return self.vlan < other.vlan


class SwitchConfigUpdate(pydantic.BaseModel):
    switch_name: str
    operation: OperationEnum

    vlans: List[Vlan] = None
    vxlan_maps: List[VXLANMapping] = None
    bgp: BGP = None
    ifaces: List[IfaceConfig] = None  # noqa: E701 (pyflakes bug)
    vlan_ifaces: List[VlanIface] = None

    @classmethod
    def make_object_from_net_data(self, vxlan_map, net_host_map):
        pass

    def sort(self):
        # in case we want to compare this or ship it to the user we may benefit from it being sorted
        # also test cases would fail otherwise
        if self.vlans:
            self.vlans.sort()
        if self.vxlan_maps:
            self.vxlan_maps.sort()
        if self.ifaces:
            self.ifaces.sort()
            for iface in self.ifaces:
                iface.sort()
        if self.bgp:
            self.bgp.sort()
        if self.vlan_ifaces:
            self.vlan_ifaces.sort()

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

    def add_vlan_iface(self, **kwargs):
        if not self.vlan_ifaces:
            self.vlan_ifaces = []
        vif = VlanIface(**kwargs)
        self.vlan_ifaces.append(vif)


class SwitchConfigUpdateList:
    def __init__(self, operation, drv_conf):
        self.operation = operation
        self.drv_conf = drv_conf
        self.switch_config_updates = {}

    def get_or_create_switch(self, switch_name):
        if switch_name not in self.switch_config_updates:
            self.switch_config_updates[switch_name] = SwitchConfigUpdate(switch_name=switch_name,
                                                                         operation=self.operation)
        return self.switch_config_updates[switch_name]

    def add_binding_host_to_config(self, hg_config, network_id, seg_vni, seg_vlan, trunk_vlan=None,
                                   keep_mapping=False, exclude_hosts=None, is_bgw=False, gateways=None):
        """Add binding host config to all required switches

        Given a hostgroup config this method generates and adds config to this
        config request. "Add" means that the config will be added, the overall
        operation (add, remove, replace) is determined by self.operation.

        Params:
         * keep_mapping: determines if the vlan-vni mapping is kept on op=remove/replace
         * exclude_hosts: hosts to exclude if a metagroup is being bound
         * is_bgw: bordergateway mode - no ifaces will be configured, bgp stanzas marked as bgw
         * gateways: all gateways configured for this binding host ({'vrf': name, 'ips': [gw, gw, gw]})
        """
        add = self.operation == OperationEnum.add
        for switch_name, switchports in hg_config.iter_switchports(self.drv_conf, exclude_hosts=exclude_hosts):
            switch = self.drv_conf.get_switch_by_name(switch_name)
            scu = self.get_or_create_switch(switch.name)

            # add bgp stuff
            if seg_vni and (add or not keep_mapping):
                sg = self.drv_conf.get_switchgroup_by_switch_name(switch.name)
                switch_az_num = self.drv_conf.global_config.get_availability_zone(sg.availability_zone).number
                if not scu.bgp:
                    scu.bgp = BGP(asn=sg.asn, asn_region=self.drv_conf.global_config.asn_region,
                                  switchgroup_id=sg.group_id)
                scu.bgp.add_vlan(seg_vlan, seg_vni, switch_az_num, bgw_mode=is_bgw)

            # vlan-vxlan mapping
            if seg_vni and (add or not keep_mapping):
                scu.add_vlan(seg_vlan, network_id)
                scu.add_vxlan_map(seg_vni, seg_vlan)

            # gateways
            if gateways:
                scu.add_vlan_iface(vlan=seg_vlan, vrf=gateways['vrf'], primary_ip=gateways['ips'][0],
                                   secondary_ips=gateways['ips'][1:])

            # interface config
            if not is_bgw:
                for sp in switchports:
                    if sp.unmanaged:
                        continue
                    iface = scu.get_or_create_iface_from_switchport(sp)
                    iface.add_trunk_vlan(seg_vlan)

                    if hg_config.direct_binding and not hg_config.role:
                        if trunk_vlan:
                            iface.add_vlan_translation(seg_vlan, trunk_vlan)
                        elif not hg_config.allow_multiple_trunk_ports:
                            iface.native_vlan = seg_vlan

    def add_vrf_bgp_config(self, switch_names, vrf_name, vrf_networks, vrf_aggregates):
        for switch_name in switch_names:
            scu = self.get_or_create_switch(switch_name)
            vrf = scu.bgp.get_or_create_vrf(vrf_name)

            networks = []
            curr_networks = [(net.network, net.az_local, net.ext_announcable) for net in (vrf.networks or [])]
            for network, az_local, ext_announcable in vrf_networks:
                if (network, az_local, ext_announcable) not in curr_networks:
                    networks.append(BGPVRFNetwork(network=network, az_local=az_local, ext_announcable=ext_announcable))
            vrf.add_networks(networks)

            aggregates = []
            curr_aggregates = [(agg.network, agg.az_local) for agg in (vrf.aggregates or [])]
            for network, az_local in vrf_aggregates:
                if (network, az_local) not in curr_aggregates:
                    aggregates.append(BGPVRFAggregate(network=network, az_local=az_local))
            vrf.add_aggregates(aggregates)

    def add_infra_networks_from_hostgroup(self, hg_config, sg):
        for inet in hg_config.infra_networks or []:
            # FIXME: exclude hosts
            gateways = None
            if inet.vrf:
                gateways = {'vrf': inet.vrf, 'ips': inet.networks}

            self.add_binding_host_to_config(hg_config, inet.name, inet.vni, inet.vlan,
                                            gateways=gateways)

            if inet.vrf:
                # get network address from network (clear host bits); they are az-local and non-ext-announcable
                # add_vrf_bgp_config() network inputs: (network, az_local, ext_announcable)
                nets = [(str(ipaddress.ip_network(net, strict=False)), True, False)
                        for net in inet.networks]
                # aggregates are az-local
                # add_vrf_bgp_config() network inputs: (network, az_local)
                aggs = [(agg, True) for agg in inet.aggregates]

                self.add_vrf_bgp_config(hg_config.get_switch_names(self.drv_conf), inet.vrf, nets, aggs)

    def add_extra_vlans(self, hg_config, exclude_hosts=None):
        """Add extra vlans to interfaces, which only appear in the 'allowed trunk vlans' list"""
        if not hg_config.extra_vlans:
            return

        for switch_name, switchports in hg_config.iter_switchports(self.drv_conf, exclude_hosts=exclude_hosts):
            switch = self.drv_conf.get_switch_by_name(switch_name)
            scu = self.get_or_create_switch(switch.name)

            for sp in switchports:
                if sp.unmanaged:
                    continue
                iface = scu.get_or_create_iface_from_switchport(sp)
                for extra_vlan in hg_config.extra_vlans:
                    iface.add_trunk_vlan(extra_vlan)

    def clean_switches(self, switch_names):
        for cfg_switch in list(self.switch_config_updates):
            if cfg_switch not in switch_names:
                del self.switch_config_updates[cfg_switch]

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
