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
from typing import List, Union

import pydantic

from networking_ccloud.common import constants as c_const

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

    # netbox: device.device_types.manufacturer
    vendor: str
    # injected from secrets
    user: str
    password: str

    # will be calculated from hostname
    bgp_source_ip: str

    _normalize_host = pydantic.validator('host', allow_reuse=True)(validate_ip_address)
    _normalize_bgp_source_ip = pydantic.validator('bgp_source_ip', allow_reuse=True)(validate_ip_address)


# FIXME: put into consts
roles = ["vpod", "stpod", "apod", "bgw"]


class RoleEnum(str, Enum):
    vpod = "vpod"
    stpod = "stpod"
    apod = "apod"
    bgw = "bgw"


class SwitchGroup(pydantic.BaseModel):
    name: str
    members: List[Switch]

    # netbox: device.site.slug
    availability_zone: str

    # FIXME: get from driver consts
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
        return self.override_vlan_pool or self.name

    @pydantic.validator('members')
    def validate_members(cls, v):
        # we currently plan with having exactly two members in each group
        if len(v) != 2:
            raise ValueError(f"Expected two switch members, got {len(v)} - "
                             "the code should work with other member counts, but this "
                             "should be checked beforehand")

        # members need to be of the same vendor
        vendors = set(s.vendor for s in v)
        if len(vendors) > 1:
            raise ValueError("Switchgroup members need to have the same vendor! Found {}"
                             .format(", ".join(f"{s.name} of type {s.vendor}" for s in v)))

        # check if the vendor is supported
        # FIXME: use ccloud_const
        vendor = vendors.pop()
        if vendor not in ('arista', 'cisco'):
            raise ValueError(f"Vendor {vendors[0]} is not supported by this driver (yet)")

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
    members: List[str] = None

    @pydantic.root_validator
    def only_allow_members_with_lacp_enabled(cls, v):
        if v['members'] and not v['lacp']:
            raise ValueError(f"SwitchPort {v['switch']}/{v['name']} has LACP members without LACP being enabled")
        if not v['members'] and v['lacp']:
            raise ValueError(f"SwitchPort {v['switch']}/{v['name']} is LACP port and has no members")
        return v

    @pydantic.root_validator
    def check_port_name_in_lacp_mode(cls, values):
        # see FIXME above, we need a parsable portchannel id somewhere
        # FIXME: implement
        return values


class HostGroup(pydantic.BaseModel):
    # FIXME: proper handover mode checking (like with roles)
    # FIXME: shall lacp member ports explicitly have their ports listed as single members or explicitly not
    # FIXME: add computed value "vlan_pool" or name or anything like this
    handover_mode: Union['vlan'] = c_const.HANDOVER_VLAN

    binding_hosts: List[str]
    metagroup: bool = False

    # members are either switchports or other hostgroups
    members: Union[List[SwitchPort], List[str]]

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


class DriverConfig(pydantic.BaseModel):
    switchgroups: List[SwitchGroup]
    hostgroups: List[HostGroup]

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

    def get_vendors(self):
        v = set()
        for sg in self.switchgroups:
            for s in sg.members:
                v.add(s.vendor)
        return v
