import ipaddress
import re
from typing import List, Union

import pydantic

ip46addr_type = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


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

class Switch(pydantic.BaseModel):
    # netbox: dcim.devices

    # netbox: device.hostname
    name: str
    host: ip46addr_type

    # netbox: device.device_types.manufacturer
    vendor: str
    # injected from secrets
    user: str
    password: str

    # will be calculated from hostname
    ip_loopback0: ip46addr_type


class SwitchGroup(pydantic.BaseModel):
    name: str
    members: List[Switch]

    # netbox: device.site.slug
    availability_zone: str

    # FIXME: get from driver consts
    role: Union['vpod', 'stpod', 'apod', 'bgw']

    # calculated from member-hostnames
    ip_loopback1: ip46addr_type
    asn: str

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
                             .format(", ".join(f"{s.name} of typse {s.vendor}" for s in v)))

        # check if the vendor is supported
        # FIXME: use ccloud_const
        if vendors[0] not in ('arista', 'cisco'):
            raise ValueError(f"Vendor {vendors[0]} is not supported by this driver (yet)")

        return v

    @pydantic.validator('asn')
    def validate_asn(cls, v):
        # 65000 or 65000.123
        m = re.match(r"^(?P<first>\d+)(?:\.(?P<second>\d+)$", v)
        if not m:
            raise ValueError(f"asn value '{v}' is not a valid AS number")

        asn = int(m.group('first'))
        if m.group('second'):
            # dot notation
            asn = (asn << 16) + int(m.group('second'))

        if not (0 < asn < (2 ** 32)):
            raise ValueError(f"asn value '{v}' is out of range")


class SwitchPort(pydantic.BaseModel):
    # FIXME: for LACP is the name just Port-Channel<id>? do we need to parse the id? if so, extra validation
    switch: str
    name: str
    lacp: bool = False
    members: List[str]

    @pydantic.root_validator
    def only_allow_members_with_lacp_enabled(cls, v):
        if v['members'] and not v.get('lacp', False):
            raise ValueError(f"SwitchPort {v['switch']}/{v['name']} has LACP members without LACP being enabled")
        return v

    @pydantic.root_validator
    def check_port_name_in_lacp_mode(cls, v):
        # see FIXME above, we need a parsable portchannel id somewhere
        pass


class HostGroup(pydantic.BaseModel):
    # FIXME make vlan a constant in driver
    handover_mode: Union['vlan'] = 'vlan'

    binding_hosts: List[str]

    @pydantic.root_validator
    def ensure_at_least_one_binding_host(cls, v):
        pass


class DriverConfig(pydantic.BaseModel):
    switchgroups: List[SwitchGroup]
    hostgroups: List[HostGroup]

    @pydantic.root_validator
    def check_all_ports_in_hostgroup_map_to_same_vlan_pool(cls, values):
        pass

    @pydantic.root_validator
    def check_referenced_switches_exist(cls, values):
        pass
