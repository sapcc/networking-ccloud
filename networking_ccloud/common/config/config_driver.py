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
from itertools import groupby
from operator import attrgetter
import re
from typing import Dict, List, Union

import pydantic

from networking_ccloud.common import constants as cc_const

# FIXME: we want to have a good format for field descriptions
#   Option a: if pydantic has something to embed it into the schema we should use it
#   Option b: add a comment before each field so we know what it is for
#   The Netbox mapping should either be removed or get its own format (# netbox: device.name)

# FIXME: we need to define vlan pool ranges
#   Option a:
#       - default range in DriverConfig
#       - only explicitly define when/if we need to override them
#   Option b:
#       - ...unclear


def validate_ip_address(addr: str) -> str:
    # raises a ValueError if not a valid ip address
    ipaddress.ip_address(addr)

    return addr


def validate_vlan_ranges(vlan_range: str) -> str:
    m = re.match(r"^(?P<start>\d+):(?P<end>\d+)$", vlan_range)
    if not m:
        raise ValueError(f"Vlan range '{vlan_range}' is not in format $start_num:$end_num")
    if not (2 <= int(m.group('start')) <= 4095 and 2 <= int(m.group('end')) <= 4095):
        raise ValueError(f"Both parts of '{vlan_range}' need to be in range of [2, 4095]")
    if int(m.group('start')) > int(m.group('end')):
        raise ValueError(f"Vlan range '{vlan_range}' needs to have a start that is lower or equal to its end")
    return vlan_range


def validate_asn(asn):
    # 65000 or 65000.123
    asn = str(asn)
    m = re.match(r"^(?P<first>\d+)(?:\.(?P<second>\d+))?$", asn)
    if not m:
        raise ValueError(f"asn value '{asn}' is not a valid AS number")

    asn = int(m.group('first'))
    if m.group('second'):
        # dot notation
        asn = (asn << 16) + int(m.group('second'))

    if not (0 < asn < (2 ** 32)):
        raise ValueError(f"asn value '{asn}' is out of range")

    if asn >= 2 ** 16:
        return f"{asn >> 16}.{asn & 0xFFFF}"
    else:
        return str(asn)


class Switch(pydantic.BaseModel):
    # netbox: dcim.devices

    # netbox: device.hostname
    name: str
    host: str

    # netbox: device.platform.slug
    platform: str
    # injected from secrets
    user: str
    password: str

    # will be calculated from hostname
    bgp_source_ip: str

    _normalize_host = pydantic.validator('host', allow_reuse=True)(validate_ip_address)
    _normalize_bgp_source_ip = pydantic.validator('bgp_source_ip', allow_reuse=True)(validate_ip_address)
    _allow_test_platform = False  # only used by the tests

    @pydantic.validator('platform')
    def validate_platform(cls, v):
        # check if the platform is supported
        if not (v in cc_const.PLATFORMS or (v == "test" and cls._allow_test_platform)):
            raise ValueError(f"Platform '{v}' is not supported by this driver (yet)")

        return v


class HostgroupRole(str, Enum):
    transit = cc_const.DEVICE_TYPE_TRANSIT
    bgw = cc_const.DEVICE_TYPE_BGW


class HandoverMode(str, Enum):
    vlan = cc_const.HANDOVER_VLAN


class SwitchGroup(pydantic.BaseModel):
    name: str
    members: List[Switch]

    # netbox: device.site.slug
    availability_zone: str

    # calculated from member-hostnames
    vtep_ip: str
    asn: str
    group_id: pydantic.conint(ge=0, lt=2 ** 16)

    override_vlan_pool: str = None
    vlan_ranges: List[str] = None

    _normalize_vtep_ip = pydantic.validator('vtep_ip', allow_reuse=True)(validate_ip_address)
    _normalize_asn = pydantic.validator('asn', allow_reuse=True)(validate_asn)
    _normalize_vlan_ranges = pydantic.validator('vlan_ranges',
                                                each_item=True, allow_reuse=True)(validate_vlan_ranges)

    @property
    def vlan_pool(self):
        # FIXME: maybe, probably, we want to rename this to physnet / physical_network
        return self.override_vlan_pool or self.name

    @pydantic.validator('members')
    def validate_members(cls, v):
        # we currently plan with having exactly two members in each group
        if len(v) != 2:
            raise ValueError(f"Expected two switch members, got {len(v)} - "
                             "the code should work with other member counts, but this "
                             "should be checked beforehand")

        # members need to be of the same platform
        platforms = set(s.platform for s in v)
        if len(platforms) > 1:
            raise ValueError("Switchgroup members need to have the same platform! Found {}"
                             .format(", ".join(f"{s.name} of type {s.platform}" for s in v)))

        return v

    @pydantic.validator('availability_zone')
    def validate_availability_zone(cls, v):
        return v.lower()

    def get_managed_vlans(self, drv_conf, with_infra_nets=False):
        """Get a list of all vlans that we manage on this switch"""
        vlan_ranges = self.vlan_ranges
        if not vlan_ranges:
            vlan_ranges = drv_conf.global_config.default_vlan_ranges

        all_ranges = set()
        for vlan_range in vlan_ranges:
            start, end = vlan_range.split(":")
            all_ranges |= set(range(int(start), int(end) + 1))

        if with_infra_nets:
            for hg in drv_conf.hostgroups:
                if not hg.infra_networks:
                    continue
                if not hg.has_switches_as_member(drv_conf, [sw.name for sw in self.members]):
                    continue
                all_ranges |= set(infra_net.vlan for infra_net in hg.infra_networks)

        return all_ranges


class SwitchPort(pydantic.BaseModel):
    # FIXME: for LACP is the name just Port-Channel<id>? do we need to parse the id? if so, extra validation
    switch: str
    name: str = None
    lacp: bool = False
    portchannel_id: pydantic.conint(gt=0) = None
    members: List[str] = None
    unmanaged: bool = False

    @pydantic.root_validator
    def only_allow_members_and_pc_id_with_lacp_enabled(cls, v):
        if v['members'] and not v['lacp']:
            raise ValueError(f"SwitchPort {v['switch']}/{v['name']} has LACP members without LACP being enabled")
        if not v['members'] and v['lacp']:
            raise ValueError(f"SwitchPort {v['switch']}/{v['name']} is LACP port and has no members")
        if v['portchannel_id'] and not v['lacp']:
            raise ValueError(f"SwitchPort {v['switch']}/{v['name']} has a portchannel id set without "
                             "LACP being enabled")
        return v

    @pydantic.root_validator
    def set_portchannel_id_for_lacp(cls, values):
        if values['lacp'] and not values['portchannel_id']:
            m = re.match(r"^port-channel\s*(?P<pc_id>\d+)$", values['name'].lower())
            if not m:
                raise ValueError(f"No pc id given for {values['switch']}/{values['name']} and could not parse one "
                                 f"from interface name")
            values['portchannel_id'] = int(m.group('pc_id'))
        return values

    @pydantic.root_validator
    def check_port_name_in_lacp_mode(cls, values):
        # see FIXME above, we need a parsable portchannel id somewhere
        # FIXME: implement
        return values


class InfraNetwork(pydantic.BaseModel):
    name: str
    vlan: pydantic.conint(gt=1, lt=4095)
    vrf: str = None
    networks: List[str] = []
    aggregates: List[str] = []
    vni: pydantic.conint(gt=0, lt=2**24)
    untagged: bool = False
    dhcp_relays: List[str] = []

    _normalize_relays = pydantic.validator('dhcp_relays', each_item=True, allow_reuse=True)(validate_ip_address)

    def __hash__(self) -> int:
        return hash((self.name, self.vlan, self.vrf, tuple(self.networks),
                    self.vni, self.untagged, tuple(self.dhcp_relays)))

    @pydantic.validator('networks', each_item=True)
    def ensure_host_bit_set(cls, net):
        net = ipaddress.ip_interface(net)
        if str(net) == str(net.network):
            raise ValueError(f'Network {net} is supposed to be used as gateway and hence needs hosts bits set')
        return str(net)

    @pydantic.validator('aggregates', each_item=True)
    def ensure_network(cls, net):
        # raises ValueError if host bits are set
        net = ipaddress.ip_network(net, strict=True)
        return str(net)

    @pydantic.root_validator
    def ensure_correct_value_combination(cls, values):
        if len(values.get('networks')) > 0 and not bool(values.get('vrf')):
            raise ValueError("If network is given a VRF must be set too")
        if len(values.get('dhcp_relays')) > 0 and not len(values.get('networks')) > 0:
            raise ValueError("If dhcp_relays is given a network must be present too")
        if len(values.get('aggregates', [])) > len(values.get('networks', [])):
            raise ValueError('There are more aggregates than networks')
        return values

    @pydantic.root_validator
    def ensure_dhcp_relay_not_in_networks(cls, values):
        for network in values.get('networks', []):
            network = ipaddress.ip_interface(network)
            for relay in values.get('dhcp_relays', []):
                relay = ipaddress.ip_address(relay)
                if relay in network.network:
                    raise ValueError(f'dhcp_relay {relay} is contained in network {network}')
        return values

    @pydantic.root_validator
    def ensure_aggregate_is_supernet_of_networks(cls, values):
        for aggregate in values.get('aggregates', []):
            aggregate = ipaddress.ip_network(aggregate)
            if any(ipaddress.ip_interface(x).network == aggregate for x in values.get('networks', [])):
                raise ValueError(f'Aggregate {aggregate} is equal to one of the networks')
            if not any(ipaddress.ip_interface(x) in aggregate for x in values.get('networks', [])):
                raise ValueError(f'Aggregate {aggregate} is not a supernet of any network in networks')
        return values


class Hostgroup(pydantic.BaseModel):
    # FIXME: proper handover mode checking (like with roles)
    # FIXME: shall lacp member ports explicitly have their ports listed as single members or explicitly not
    # FIXME: add computed value "vlan_pool" or name or anything like this
    handover_mode: HandoverMode = cc_const.HANDOVER_VLAN

    binding_hosts: List[str]
    metagroup: bool = False

    # direct binding means no HPB (default: true for normal groups, false for metagroups)
    direct_binding: bool

    # members are either switchports or other hostgroups
    members: Union[List[SwitchPort], List[str]]

    # bgw/transit role
    role: HostgroupRole = None
    handle_availability_zones: List[str] = None

    # infra networks attached to hostgroup
    infra_networks: List[InfraNetwork] = []

    # vlans that are added to all allowed-vlan list without managing the vlan on switch
    extra_vlans: List[pydantic.conint(gt=1, lt=4095)] = None

    _vlan_pool: str = None

    class Config:
        use_enum_values = True
        underscore_attrs_are_private = True

    @pydantic.validator('binding_hosts')
    def ensure_at_least_one_binding_host(cls, v):
        if len(v) == 0:
            raise ValueError("Hostgroup needs to have at least one binding host")
        return v

    @pydantic.validator('members')
    def ensure_at_least_one_member(cls, v):
        if len(v) == 0:
            raise ValueError("Hostgroup needs to have at least one member")
        return v

    @pydantic.root_validator()
    def ensure_hostgroups_with_role_are_not_a_metagroup(cls, values):
        # FIXME: constants? enum? what do we do here
        if values.get("role") and values.get("metagroup"):
            raise ValueError("transits/bgws cannot be a metagroup")
        return values

    @pydantic.root_validator
    def ensure_hostgroups_with_role_have_an_az(cls, values):
        if values.get('role') and not values.get('handle_availability_zones'):
            raise ValueError("Hostgroups for bgws/tranits need to have a list of AZs they handle")
        if not values.get('role') and values.get('handle_availability_zones'):
            raise ValueError("Normal Hostgroups cannot have handle_availability_zones set")
        return values

    @pydantic.root_validator
    def ensure_hostgroups_with_role_have_only_one_binding_host(cls, values):
        # Allow only one binding host per role-group, as we use it as group-name
        if values.get('role') and len(values.get('binding_hosts', [])) > 1:
            raise ValueError("Hostgroups for bgws/tranits can currently only have a single binding host")
        return values

    @pydantic.root_validator
    def ensure_hostgroups_with_role_are_direct_binding(cls, values):
        if values.get('role') and not values.get('direct_binding'):
            raise ValueError("Hostgroups for bgws/tranits need to be direct bindings")
        return values

    @pydantic.root_validator
    def ensure_members_and_metaflag_match(cls, values):
        if 'members' in values:
            metagroup = values.get('metagroup')
            is_switchport = isinstance(values['members'][0], SwitchPort)
            if metagroup and is_switchport:
                raise ValueError("Metagroups can't have SwitchPorts as members")
            if not metagroup and not is_switchport:
                raise ValueError("Non-metagroups need to have SwitchPorts as members")
        return values

    @pydantic.root_validator
    def ensure_bgw_members_have_no_ports_but_everyone_else_has(cls, values):
        if 'members' in values and not values.get('metagroup'):
            is_bgw = values.get('role') == HostgroupRole.bgw
            for sp in values.get('members', []):
                if is_bgw and sp.name:
                    raise ValueError(f"Hostgroup {values.get('binding_hosts')} with role bgw "
                                     "cannot have named switchports")
                if not is_bgw and not sp.name:
                    raise ValueError(f"Hostgroup {values.get('binding_hosts')} needs to have names for each switchport")

        return values

    @pydantic.root_validator
    def check_same_port_channel_id(cls, values):
        # NOTE: this check only works under the assumption that each group has only a single portchannel id
        #       with this we ensure that we don't accidentally add a host with two different pc ids on a switchgroup
        #       if this assumption breaks, we will need to remove this
        # FIXME: implement
        return values

    @pydantic.root_validator(pre=True)
    def set_default_for_direct_binding(cls, values):
        v = values.get('direct_binding')
        if v is None:
            # default false for metagroups, true for normal groups
            values['direct_binding'] = not values.get('metagroup', False)
        return values

    @property
    def binding_host_name(self):
        """Generate a name for this hostgroup by joining all binding hosts"""
        return ",".join(self.binding_hosts)

    def get_any_switchgroup(self, drv_conf):
        """Find one switchgroup this hostgroup is connected to

        In many cases we only need any switchgroup, not all of them, as
        all switchgroups of a host share the same attribute, like the
        vlan pool name or availability zone
        """
        # FIXME: prime candidate for caching, once we know what we're doing with cfg reloads / metagroups / pools
        if self.metagroup:
            # all metagroup members have the same switchgroup(s)
            hg = drv_conf.get_hostgroup_by_host(self.members[0])
            return hg.get_any_switchgroup(drv_conf)

        # all interfaces of a hostgroup have the same vlan pool
        return drv_conf.get_switchgroup_by_switch_name(self.members[0].switch)

    def get_availability_zone(self, drv_conf):
        return self.get_any_switchgroup(drv_conf).availability_zone

    def get_vlan_pool_name(self, drv_conf):
        """Find vlanpool name for this hostgroup"""
        if self._vlan_pool is None:
            self._vlan_pool = self.get_any_switchgroup(drv_conf).vlan_pool
        return self._vlan_pool

    def iter_switchports(self, driver_config, exclude_hosts=None):
        """Iterate over all switchports, grouped by switch

        For metagroups we iterate over all child-groups
        """
        if exclude_hosts and any(m in self.binding_hosts for m in exclude_hosts):
            return []

        if self.metagroup:
            # find all childgroups (hgs that contain a referenced binding host and have no hosts in exclude_hosts)
            children = [hg for hg in driver_config.hostgroups
                        if not hg.metagroup and any(m in hg.binding_hosts for m in self.members) and
                        all(m not in hg.binding_hosts for m in (exclude_hosts or []))]
            ifaces = [iface for child in children for iface in child.members]
        else:
            ifaces = self.members

        return groupby(sorted(ifaces, key=attrgetter('switch')), key=attrgetter('switch'))

    def get_switch_names(self, driver_config, exclude_hosts=None):
        switches = [switch_name for switch_name, _ in
                    self.iter_switchports(driver_config, exclude_hosts=exclude_hosts)]
        switches.sort()

        return switches

    def has_switches_as_member(self, drv_conf, switch_names):
        if self.metagroup:
            for member in self.members:
                far_hg = drv_conf.get_hostgroup_by_host(member)
                if far_hg.has_switches_as_member(drv_conf, switch_names):
                    return True
        else:
            for member in self.members:
                if member.switch in switch_names:
                    return True
        return False


class VRF(pydantic.BaseModel):
    name: str
    address_scopes: List[str] = []

    # magic number we use for vni, rt import/export calculation
    number: pydantic.conint(gt=0)


class AvailabilityZone(pydantic.BaseModel):
    name: str
    suffix: str
    number: pydantic.conint(gt=0, lt=10)  # needs to be one digit

    @pydantic.validator('name')
    def validate_name(cls, v):
        return v.lower()

    @pydantic.validator('suffix')
    def validate_suffix(cls, v):
        return v.lower()


class GlobalConfig(pydantic.BaseModel):
    asn_region: str
    default_vlan_ranges: List[str]
    availability_zones: List[AvailabilityZone]
    vrfs: List[VRF]

    _normalize_asn = pydantic.validator('asn_region', allow_reuse=True)(validate_asn)
    _normalize_vlan_ranges = pydantic.validator('default_vlan_ranges',
                                                each_item=True, allow_reuse=True)(validate_vlan_ranges)

    _availability_zone_map: Dict[str, AvailabilityZone] = pydantic.PrivateAttr()
    _address_scopes_to_vrf_map: Dict[str, str] = pydantic.PrivateAttr()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # cache certain mappings that we need frequently
        self._availability_zone_map = {az.name: az for az in self.availability_zones}
        self._address_scopes_to_vrf_map = {ascope: vrf.name for vrf in self.vrfs for ascope in vrf.address_scopes}

    @pydantic.validator('vrfs')
    def check_vrf_name_unique(cls, values):
        names = set()
        for vrf in values:
            if vrf.name in names:
                raise ValueError(f'VRF {vrf.name} is duplicated')
            names.add(vrf.name)
        return values

    @pydantic.validator('vrfs')
    def check_vrf_number_unique(cls, values):
        nums = set()
        for vrf in values:
            if vrf.number in nums:
                raise ValueError(f'VRF id {vrf.number} is duplicated on VRF {vrf.name}')
            nums.add(vrf.number)
        return values

    def get_availability_zone(self, az_name):
        return self._availability_zone_map.get(az_name)

    def get_vrf_name_for_address_scope(self, address_scope):
        return self._address_scopes_to_vrf_map.get(address_scope)


class DriverConfig(pydantic.BaseModel):
    global_config: GlobalConfig
    switchgroups: List[SwitchGroup]
    hostgroups: List[Hostgroup]

    _hostgroup_by_host: Dict[str, Hostgroup] = pydantic.PrivateAttr()
    _switchgroup_by_switch: Dict[str, SwitchGroup] = pydantic.PrivateAttr()
    _switch_by_name: Dict[str, Switch] = pydantic.PrivateAttr()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # cache certain mappings that we need frequently
        self._hostgroup_by_host = {binding_host: hg for hg in self.hostgroups for binding_host in hg.binding_hosts}
        self._switchgroup_by_switch = {sw.name: sg for sg in self.switchgroups for sw in sg.members}
        self._switch_by_name = {sw.name: sw for sg in self.switchgroups for sw in sg.members}

    @pydantic.root_validator
    def check_hostgroup_references(cls, values):
        # check that referenced switches exist
        # check that hosts referenced by metagroups exist
        # check all hostgroup members belong to the same vlan pool
        if 'switchgroups' not in values or 'hostgroups' not in values:
            return

        # get mapping from switch to vlanpool
        switch_vlanpool_map = {}
        for sg in values['switchgroups']:
            for switch in sg.members:
                switch_vlanpool_map[switch.name] = sg.vlan_pool

        all_hosts = set()
        host_vlanpool_map = {}
        for hg in values['hostgroups']:
            for host in hg.binding_hosts:
                # check that a host is not specified twice
                if host in all_hosts:
                    raise ValueError(f"Host {host} is bound by two hostgroups or twice in the same hostgroup")
                all_hosts.add(host)

            # check that referenced interfaces exist and don't bind two separate vlan pools
            vlan_pools = set()
            if not hg.metagroup:
                for port in hg.members:
                    # check that referenced switches exist
                    if port.switch not in switch_vlanpool_map:
                        raise ValueError(f"Switch {port.switch} referenced by hostgroup does not exist")
                    vlan_pools.add(switch_vlanpool_map[port.switch])
                # check that this hostgroup has only one vlan pool
                if len(vlan_pools) != 1:
                    raise ValueError("Hostgroup needs to be bound to exactly one vlan pool - "
                                     f"found {vlan_pools} for hostgroup with binding hosts {hg.binding_hosts}")
                vlan_pool = vlan_pools.pop()
                for host in hg.binding_hosts:
                    host_vlanpool_map[host] = vlan_pool

        # check that metagroup members actually exist and don't bind two separate vlan pools
        for hg in values['hostgroups']:
            if not hg.metagroup:
                continue
            vlan_pools = set()
            for member in hg.members:
                if member not in all_hosts:
                    raise ValueError(f"Metagroup member {member} does not exist")
                if member not in host_vlanpool_map:
                    raise ValueError(f"Metagroup member {member} cannot be part of another metagroup")
                vlan_pools.add(host_vlanpool_map[member])
                # check that this meta hostgroup has only one vlan pool
                if len(vlan_pools) != 1:
                    raise ValueError("Hostgroup needs to be bound to exactly one vlan pool - "
                                     f"found {vlan_pools} for hostgroup with binding hosts {hg.binding_hosts}")

        return values

    @pydantic.validator('hostgroups')
    def ensure_at_least_one_member(cls, v):
        ifaces = {}
        for hg in v:
            if hg.metagroup:
                continue
            for sp in hg.members:
                iface = (sp.switch, sp.name)
                hg_name = ",".join(hg.binding_hosts)
                if iface in ifaces:
                    raise ValueError(f"Iface {sp.switch}/{sp.name} is bound two times, "
                                     f"once by {hg_name} and once by {ifaces[iface]}")
                ifaces[iface] = hg_name

        return v

    @pydantic.validator('switchgroups')
    def ensure_switchgroup_id_unique(cls, v):
        group_ids = {}
        for sg in v:
            if sg.group_id in group_ids:
                raise ValueError(f"SwitchGroup {sg.name} has group id {sg.group_id}, which is already in use "
                                 f"by SwitchGroup {group_ids[sg.group_id]}")
            group_ids[sg.group_id] = sg.name

        return v

    @pydantic.root_validator
    def ensure_interconnect_az_requirements(cls, values):
        """Make sure transits service their own AZ and all others service ONLY their own AZ"""
        if values is None:
            return

        for hg in values.get('hostgroups', []):
            if hg.role is None:
                continue
            found = False
            for sg in values.get('switchgroups', []):
                for sw in sg.members:
                    if hg.members[0].switch == sw.name:
                        found = True
                        break
                if found:
                    break
            else:
                raise ValueError(f"Missing switch {hg.members[0].switch} for Hostgroup {hg.binding_host_name} "
                                 f"(should've already been verified!)")

            if sg.availability_zone not in hg.handle_availability_zones:
                raise ValueError(f"Hostgroup {hg.binding_host_name} is in AZ {sg.availability_zone}, "
                                 f"but only handles {', '.join(hg.handle_availability_zones)}")

            if hg.role != HostgroupRole.transit and len(hg.handle_availability_zones) > 1:
                raise ValueError(f"Hostgroup {hg.binding_host_name} has AZs {hg.handle_availability_zones}, but "
                                 f"should only have {sg.availability_zone}")

        return values

    @pydantic.root_validator
    def ensure_all_switchgroup_azs_exist(cls, values):
        if 'global_config' not in values:
            return values
        azs = [az.name for az in values['global_config'].availability_zones]
        for sg in values.get('switchgroups', []):
            if sg.availability_zone not in azs:
                raise ValueError(f"SwitchGroup {sg.name} has invalid az {sg.availability_zone} - "
                                 f"options are '{', '.join(azs)}'")

        return values

    @pydantic.root_validator
    def ensure_all_infra_network_vrf_exist(cls, values):
        if 'global_config' not in values:
            return values
        if 'hostgroups' not in values:
            return values
        global_config: GlobalConfig = values['global_config']
        hgs: List[Hostgroup] = values['hostgroups']
        vrf_names = set(x.name for x in global_config.vrfs)
        for hg in hgs:
            if hg.infra_networks:
                for net in hg.infra_networks:
                    if net.vrf and net.vrf not in vrf_names:
                        raise ValueError(f'Associated VRF {net.vrf} of infra network {net.name} is not existing')
        return values

    def get_platforms(self):
        """Get all platforms as a set used in the given config"""
        v = set()
        for sg in self.switchgroups:
            for s in sg.members:
                v.add(s.platform)
        return v

    def get_switches(self, platform=None):
        """Get all switches, optionally filtered by platform"""
        switches = []
        for sg in self.switchgroups:
            for sw in sg.members:
                if platform and sw.platform != platform:
                    continue
                switches.append(sw)
        return switches

    def get_hostgroup_by_host(self, host):
        return self._hostgroup_by_host.get(host)

    def get_hostgroups_by_hosts(self, hosts):
        return [self._hostgroup_by_host[host] for host in hosts if host in self._hostgroup_by_host]

    def get_hostgroups_by_switches(self, switch_names):
        """Get all hostgroups that reference this switch"""
        return [hg for hg in self.hostgroups if hg.has_switches_as_member(self, switch_names)]

    def get_switchgroup_by_switch_name(self, name):
        return self._switchgroup_by_switch.get(name)

    def get_switch_by_name(self, name):
        return self._switch_by_name.get(name)

    def get_interconnects_for_az(self, device_type, az):
        return [hg for hg in self.hostgroups
                if hg.role == device_type and az in hg.handle_availability_zones]

    def get_azs_for_hosts(self, binding_hosts, ignore_special=False):
        """Get all availability zones for a list of networks

         * binding_hosts: list of binding hosts to get the AZs for
         * ignore_special: ignore transits/bordergateways
        """
        return set(hg_config.get_availability_zone(self) for hg_config in self.get_hostgroups_by_hosts(binding_hosts)
                   if not (ignore_special and hg_config.role))

    def list_availability_zones(self):
        return sorted(az.name for az in self.global_config.availability_zones)
