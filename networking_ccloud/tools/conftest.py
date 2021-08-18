from enum import Enum
import ipaddress
import re
from typing import List, Union

import pydantic

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
    ip_loopback0: str

    _normalize_host = pydantic.validator('host', allow_reuse=True)(validate_ip_address)
    _normalize_ip_loopback0 = pydantic.validator('ip_loopback0')(validate_ip_address)


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
    ip_loopback1: str
    asn: str

    override_vlan_pool: str = None

    _normalize_ip_loopback1 = pydantic.validator('ip_loopback1', allow_reuse=True)(validate_ip_address)

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
        m = re.match(r"^(?P<first>\d+)(?:\.(?P<second>\d+))$", v)
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
    # FIXME: make vlan a constant in driver
    # FIXME: model and handle metahostgroups (nova-compute-bb123)
    handover_mode: Union['vlan'] = 'vlan'

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
    def check_all_members_in_hostgroup_map_to_same_vlan_pool(cls, values):
        # FIXME: implement
        return values

    @pydantic.root_validator
    def check_referenced_switches_exist(cls, values):
        # FIXME: implement
        return values

    @pydantic.root_validator
    def check_hostgroup_metagroup_members_exist(cls, values):
        # FIXME: implement
        return values

    @pydantic.root_validator
    def check_hostgroup_no_duplicate_binding_hosts(cls, values):
        # FIXME: implement
        return values
