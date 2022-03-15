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
from typing import List, Union

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

    def get_rt(self, vni):
        return f"{self.bgp_source_ip}:{vni}"


# FIXME: put into consts
roles = ["vpod", "stpod", "apod", "bgw"]


class RoleEnum(str, Enum):
    vpod = "vpod"
    stpod = "stpod"
    apod = "apod"
    bgw = "bgw"


class HostgroupRole(str, Enum):
    transit = cc_const.DEVICE_TYPE_TRANSIT
    bgw = cc_const.DEVICE_TYPE_BGW


class SwitchGroup(pydantic.BaseModel):
    name: str
    members: List[Switch]

    # netbox: device.site.slug
    availability_zone: str

    # FIXME: get from driver consts
    # FIXME: remove this, as we don't need it here
    # role: Union['vpod', 'stpod', 'apod', 'bgw']
    # role: RoleEnum
    role: str

    # calculated from member-hostnames
    vtep_ip: str
    asn: str

    override_vlan_pool: str = None

    _normalize_vtep_ip = pydantic.validator('vtep_ip', allow_reuse=True)(validate_ip_address)

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

    @pydantic.validator('role')
    def validate_role(cls, v):
        if v not in roles:
            raise ValueError(f"Unknown role {v}, allowed values are {roles}")
        return v

    @pydantic.validator('asn')
    def validate_asn(cls, v):
        # 65000 or 65000.123
        v = str(v)
        m = re.match(r"^(?P<first>\d+)(?:\.(?P<second>\d+))?$", v)
        if not m:
            raise ValueError(f"asn value '{v}' is not a valid AS number")

        asn = int(m.group('first'))
        if m.group('second'):
            # dot notation
            asn = (asn << 16) + int(m.group('second'))

        if not (0 < asn < (2 ** 32)):
            raise ValueError(f"asn value '{v}' is out of range")

        return v


class SwitchPort(pydantic.BaseModel):
    # FIXME: for LACP is the name just Port-Channel<id>? do we need to parse the id? if so, extra validation
    switch: str
    name: str
    lacp: bool = False
    portchannel_id: pydantic.conint(gt=0) = None
    members: List[str] = None

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
    native_vlan_pool: None
    vlan: pydantic.conint(gt=0, lt=4096)
    networks: List[str] = None
    vni: pydantic.conint(gt=0, lt=2**24) = None
    untagged: bool = False
    dhcp_relays: List[str] = None

    _normalize_networks = pydantic.validator('networks', each_item=True, allow_reuse=True)(validate_ip_address)

    @pydantic.root_validator
    def ensure_correct_value_combination(cls, values):
        # FIXME: we probably need a different logic here
        if bool(values['vni']) ^ bool(values['network']):
            raise ValueError(f"If network is set vni needs to be set and vice versa")
        return values


class Hostgroup(pydantic.BaseModel):
    # FIXME: proper handover mode checking (like with roles)
    # FIXME: shall lacp member ports explicitly have their ports listed as single members or explicitly not
    # FIXME: add computed value "vlan_pool" or name or anything like this
    handover_mode: Union['vlan'] = cc_const.HANDOVER_VLAN

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
    infra_networks: List[InfraNetwork] = None

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
        return self.get_any_switchgroup(drv_conf).vlan_pool

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


class DriverConfig(pydantic.BaseModel):
    switchgroups: List[SwitchGroup]
    hostgroups: List[Hostgroup]

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
        for hg in self.hostgroups:
            if host in hg.binding_hosts:
                return hg
        return None

    def get_hostgroups_by_hosts(self, hosts):
        hgs = []
        for hg in self.hostgroups:
            if any(host in hg.binding_hosts for host in hosts):
                hgs.append(hg)
        return hgs

    def get_switchgroup_by_switch_name(self, name):
        for sg in self.switchgroups:
            if any(s.name == name for s in sg.members):
                return sg
        return None

    def get_switch_by_name(self, name):
        for sg in self.switchgroups:
            for switch in sg.members:
                if switch.name == name:
                    return switch
        return None

    def get_interconnects_for_az(self, device_type, az):
        return [hg for hg in self.hostgroups
                if hg.role == device_type and az in hg.handle_availability_zones]
