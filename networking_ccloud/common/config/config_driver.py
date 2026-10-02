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
from typing import Annotated, Any

import pydantic

from networking_ccloud.common import constants as cc_const
from pydantic import BeforeValidator, Field, ConfigDict, AfterValidator

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


def validate_asn(asn: int | str) -> str:
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
    host: Annotated[str, AfterValidator(validate_ip_address)]
    port: int | None = None

    # netbox: device.platform.slug
    platform: str
    # injected from secrets
    user: str
    password: str

    # will be calculated from hostname
    bgp_source_ip: Annotated[str, AfterValidator(validate_ip_address)]

    _allow_test_platform = False  # only used by the tests

    @pydantic.field_validator('platform')
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
    members: list[Switch]

    # netbox: device.site.slug
    availability_zone: str

    # calculated from member-hostnames
    vtep_ip: Annotated[str, AfterValidator(validate_ip_address)]
    asn: Annotated[str, BeforeValidator(validate_asn)]

    group_id: Annotated[int, Field(ge=0, lt=2 ** 16)]

    override_vlan_pool: str | None = None
    vlan_ranges: list[str] | None = None

    @pydantic.field_validator("vlan_ranges")
    @classmethod
    def normalize_vlan_ranges(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None

        # Replaces Pydantic v1's `each_item=True`
        return [validate_vlan_ranges(vlan_range) for vlan_range in value]

    @property
    def vlan_pool(self):
        # FIXME: maybe, probably, we want to rename this to physnet / physical_network
        return self.override_vlan_pool or self.name

    @pydantic.field_validator("members")
    @classmethod
    def validate_members(cls, v: list[Switch]) -> list[Switch]:
        # we currently plan having two or more members in each group
        if len(v) < 2:
            raise ValueError(f"Expected two or more switch members, got {len(v)}")

        return v

    @pydantic.field_validator("availability_zone")
    @classmethod
    def validate_availability_zone(cls, v: str) -> str:
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
                all_ranges |= {infra_net.vlan for infra_net in hg.infra_networks}

        return all_ranges


class SwitchPort(pydantic.BaseModel):
    # FIXME: for LACP is the name just Port-Channel<id>? do we need to parse the id? if so, extra validation
    switch: str
    name: str | None = None
    lacp: bool = False
    portchannel_id: Annotated[int, Field(gt=0)] | None = None
    members: list[str] | None = None
    unmanaged: bool = False

    # set interface (or member interface) speed to this vendor specific value
    speed: str | None = None

    @pydantic.model_validator(mode="after")
    def validate_switch_port(self) -> "SwitchPort":
        if self.members and not self.lacp:
            raise ValueError(f"SwitchPort {self.switch}/{self.name} has LACP members without LACP being enabled")
        if not self.members and self.lacp:
            raise ValueError(f"SwitchPort {self.switch}/{self.name} is LACP port and has no members")
        if self.portchannel_id and not self.lacp:
            raise ValueError(f"SwitchPort {self.switch}/{self.name} has a portchannel id set without "
                             "LACP being enabled")
        if self.lacp and not self.portchannel_id:
            assert self.name is not None
            m = re.match(r"^(?:port-channel|po)\s*(?P<pc_id>\d+)$", self.name.lower())
            if not m:
                raise ValueError(f"No pc id given for {self.switch}/{self.name} and could not parse one "
                                 f"from interface name")
            self.portchannel_id = int(m.group('pc_id'))

        return self


class InfraNetwork(pydantic.BaseModel):
    name: str
    vlan: Annotated[int, Field(gt=1, lt=4095)]
    vrf: str | None = None
    networks: list[str] = Field(default_factory=list)
    aggregates: list[str] = Field(default_factory=list)
    vni: Annotated[int, Field(gt=0, lt=2**24)]

    # note that untagged OpenStack network will take precedence over untagged infra networks
    untagged: bool = False
    dhcp_relays: list[str] = Field(default_factory=list)

    @pydantic.field_validator("dhcp_relays")
    @classmethod
    def normalize_relays(cls, relays: list[str]) -> list[str]:
        return [validate_ip_address(relay) for relay in relays]

    def __hash__(self) -> int:
        return hash((self.name, self.vlan, self.vrf, tuple(self.networks),
                    self.vni, self.untagged, tuple(self.dhcp_relays)))

    @pydantic.field_validator("networks")
    @classmethod
    def ensure_host_bit_set(cls, networks: list[str]) -> list[str]:
        result = []

        for net in networks:
            iface = ipaddress.ip_interface(net)

            if str(iface) == str(iface.network):
                raise ValueError(
                    f"Network {iface} is supposed to be used as gateway "
                    "and hence needs hosts bits set"
                )

            result.append(str(iface))

        return result

    @pydantic.field_validator("aggregates")
    @classmethod
    def ensure_network(cls, aggregates: list[str]) -> list[str]:
        validated_aggregates = []

        for net in aggregates:
            # raises ValueError if host bits are set
            network = ipaddress.ip_network(net, strict=True)
            validated_aggregates.append(str(network))

        return validated_aggregates

    @pydantic.model_validator(mode="after")
    def ensure_correct_value_combination(self) -> "InfraNetwork":
        if self.networks and not self.vrf:
            raise ValueError("If network is given a VRF must be set too")
        if self.dhcp_relays and not self.networks:
            raise ValueError("If dhcp_relays is given a network must be present too")
        if len(self.aggregates) > len(self.networks):
            raise ValueError('There are more aggregates than networks')
        return self

    @pydantic.model_validator(mode="after")
    def ensure_dhcp_relay_not_in_networks(self) -> "InfraNetwork":
        for net in self.networks:
            network = ipaddress.ip_interface(net)
            for r in self.dhcp_relays:
                relay = ipaddress.ip_address(r)
                if relay in network.network:
                    raise ValueError(f'dhcp_relay {relay} is contained in network {network}')
        return self

    @pydantic.model_validator(mode="after")
    def ensure_aggregate_is_supernet_of_networks(self) -> "InfraNetwork":
        for agg in self.aggregates:
            aggregate = ipaddress.ip_network(agg)
            if any(ipaddress.ip_interface(x).network == aggregate for x in self.networks):
                raise ValueError(f'Aggregate {aggregate} is equal to one of the networks')
            if not any(ipaddress.ip_interface(x) in aggregate for x in self.networks):
                raise ValueError(f'Aggregate {aggregate} is not a supernet of any network in networks')
        return self


class Hostgroup(pydantic.BaseModel):
    # FIXME: proper handover mode checking (like with roles)
    # FIXME: shall lacp member ports explicitly have their ports listed as single members or explicitly not
    # FIXME: add computed value "vlan_pool" or name or anything like this
    handover_mode: HandoverMode = HandoverMode.vlan

    binding_hosts: list[str]
    metagroup: bool = False

    # direct binding means no HPB (default: true for normal groups, false for metagroups)
    direct_binding: bool

    # members are either switchports or other hostgroups
    members: list[SwitchPort] | list[str]

    # bgw/transit role
    role: HostgroupRole | None = None
    handle_availability_zones: list[str] = Field(default_factory=list)

    # infra networks attached to hostgroup
    infra_networks: list[InfraNetwork] = Field(default_factory=list)

    # vlans that are added to all allowed-vlan list without managing the vlan on switch
    extra_vlans: list[Annotated[int, Field(gt=1, lt=4095)]] | None = None

    # allow multiple trunks per hostgroup, not setting the native vlan then (direct bindings only)
    # note that this means that no native vlan will be set for ports in this hostgroup, ever
    allow_multiple_trunk_ports: bool = False

    _vlan_pool: str | None = None
    model_config = ConfigDict(use_enum_values=True)

    @pydantic.field_validator("binding_hosts")
    @classmethod
    def ensure_at_least_one_binding_host(cls, v: list[str]) -> list[str]:
        if len(v) == 0:
            raise ValueError("Hostgroup needs to have at least one binding host")
        return v

    @pydantic.field_validator("members")
    @classmethod
    def ensure_at_least_one_member(cls, v: list[SwitchPort] | list[str]) -> list[SwitchPort] | list[str]:
        if len(v) == 0:
            raise ValueError("Hostgroup needs to have at least one member")
        return v

    @pydantic.field_validator("infra_networks")
    @classmethod
    def ensure_only_one_untagged_infra_network(cls, v: list[InfraNetwork]) -> list[InfraNetwork]:
        untagged_net = None
        for infra_net in v or []:
            if not infra_net.untagged:
                continue
            if untagged_net is None:
                untagged_net = infra_net.name
            else:
                raise ValueError("Found two untagged InfraNetworks on same hostgroup: "
                                 f"{untagged_net} and {infra_net.name}")
        return v

    @pydantic.model_validator(mode="before")
    @classmethod
    def set_default_for_direct_binding(cls, data):
        if not isinstance(data, dict) or data.get("direct_binding") is not None:
            return data

        data = data.copy()
        data["direct_binding"] = not data.get("metagroup", False)
        return data

    @pydantic.model_validator(mode="after")
    def ensure_hostgroups_with_role_are_not_a_metagroup(self):
        # FIXME: constants? enum? what do we do here
        if self.role and self.metagroup:
            raise ValueError("transits/bgws cannot be a metagroup")
        return self

    @pydantic.model_validator(mode="after")
    def ensure_hostgroups_with_role_have_an_az(self):
        if self.role and not self.handle_availability_zones:
            raise ValueError("Hostgroups for bgws/tranits need to have a list of AZs they handle")
        if not self.role and self.handle_availability_zones:
            raise ValueError("Normal Hostgroups cannot have handle_availability_zones set")
        return self

    @pydantic.model_validator(mode="after")
    def ensure_hostgroups_with_role_have_only_one_binding_host(self):
        # Allow only one binding host per role-group, as we use it as group-name
        if self.role and len(self.binding_hosts) > 1:
            raise ValueError("Hostgroups for bgws/tranits can currently only have a single binding host")
        return self

    @pydantic.model_validator(mode="after")
    def ensure_hostgroups_with_role_are_direct_binding(self):
        if self.role and not self.direct_binding:
            raise ValueError("Hostgroups for bgws/tranits need to be direct bindings")
        return self

    @pydantic.model_validator(mode="after")
    def ensure_allow_multiple_trunk_ports_are_direct_binding(self):
        if self.allow_multiple_trunk_ports and not self.direct_binding:
            raise ValueError("allow_multiple_trunk_ports can only be set for direct binding hostgroups")
        return self

    @pydantic.model_validator(mode="after")
    def ensure_members_and_metaflag_match(self):
        is_switchport = isinstance(self.members[0], SwitchPort)
        if self.metagroup and is_switchport:
            raise ValueError("Metagroups can't have SwitchPorts as members")
        if not self.metagroup and not is_switchport:
            raise ValueError("Non-metagroups need to have SwitchPorts as members")
        return self

    @pydantic.model_validator(mode="after")
    def ensure_bgw_members_have_no_ports_but_everyone_else_has(self):
        if self.members and not self.metagroup:
            is_bgw = self.role == HostgroupRole.bgw
            for sp in self.members:
                if not isinstance(sp, SwitchPort):
                    continue
                if is_bgw and sp.name:
                    raise ValueError(f"Hostgroup {self.binding_hosts} with role bgw "
                                     "cannot have named switchports")
                if not is_bgw and not sp.name:
                    raise ValueError(f"Hostgroup {self.binding_hosts} needs to have names for each switchport")

        return self

    @pydantic.model_validator(mode="after")
    def check_same_port_channel_id(self):
        # NOTE: this check only works under the assumption that each group has only a single portchannel id
        #       with this we ensure that we don't accidentally add a host with two different pc ids on a switchgroup
        #       if this assumption breaks, we will need to remove this
        # FIXME: implement
        return self

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

    def get_parent_metagroup(self, drv_conf):
        """Get metagroup for this Hostgroup, if it is part of a metagroup"""
        if self.metagroup:
            return None

        for hg in drv_conf.hostgroups:
            if any(host in hg.members for host in self.binding_hosts):
                return hg
        return None


class VRF(pydantic.BaseModel):
    name: str
    address_scopes: list[str] = Field(default_factory=list)

    # magic number we use for vni, rt import/export calculation
    number: Annotated[int, Field(gt=0)]


class AvailabilityZone(pydantic.BaseModel):
    name: str
    suffix: str
    number: Annotated[int, Field(gt=0, lt=10)]  # needs to be one digit

    @pydantic.field_validator('name', 'suffix', mode='after')
    def validate_name(cls, v):
        return v.lower()


class GlobalConfig(pydantic.BaseModel):
    asn_region: Annotated[str, BeforeValidator(validate_asn)]
    default_vlan_ranges: list[Annotated[str, AfterValidator(validate_vlan_ranges)]]
    availability_zones: list[AvailabilityZone]
    vrfs: list[VRF]

    _availability_zone_map: dict[str, AvailabilityZone]
    _address_scopes_to_vrf_map: dict[str, str]

    def model_post_init(self, __context: Any) -> None:
        """Build lookup caches after normal model validation has completed."""
        print("GlobalConfig model_post_init")
        print("vrfs", self.vrfs)
        self._availability_zone_map = {az.name: az for az in self.availability_zones}
        self._address_scopes_to_vrf_map = {
            address_scope: vrf.name
            for vrf in self.vrfs
            for address_scope in vrf.address_scopes
        }

    @pydantic.field_validator('vrfs')
    @classmethod
    def check_vrf_unique(cls, values):
        names = set()
        nums = set()
        print("check_vrf_unique", values)
        for vrf in values:
            if vrf.name in names:
                raise ValueError(f'VRF {vrf.name} is duplicated')
            if vrf.number in nums:
                raise ValueError(f'VRF id {vrf.number} is duplicated on VRF {vrf.name}')
            names.add(vrf.name)
            nums.add(vrf.number)
        return values

    def get_availability_zone(self, az_name):
        return self._availability_zone_map.get(az_name)

    def get_vrf_name_for_address_scope(self, address_scope):
        return self._address_scopes_to_vrf_map.get(address_scope)


class DriverConfig(pydantic.BaseModel):
    global_config: GlobalConfig
    switchgroups: list[SwitchGroup]
    hostgroups: list[Hostgroup]

    _hostgroup_by_host: dict[str, Hostgroup]
    _switchgroup_by_switch: dict[str, SwitchGroup]
    _switch_by_name: dict[str, Switch]

    def model_post_init(self, __context) -> None:
        # cache certain mappings that we need frequently
        self._hostgroup_by_host = {binding_host: hg for hg in self.hostgroups for binding_host in hg.binding_hosts}
        self._switchgroup_by_switch = {sw.name: sg for sg in self.switchgroups for sw in sg.members}
        self._switch_by_name = {sw.name: sw for sg in self.switchgroups for sw in sg.members}

    @pydantic.field_validator("hostgroups")
    @classmethod
    def ensure_at_least_one_member(cls, hostgroups: list[Hostgroup]) -> list[Hostgroup]:
        ifaces: dict[tuple[str, str], str] = {}

        for hg in hostgroups:
            if hg.metagroup:
                continue
            for sp in hg.members:
                iface = (sp.switch, sp.name)
                hg_name = ",".join(hg.binding_hosts)
                if iface in ifaces:
                    raise ValueError(f"Iface {sp.switch}/{sp.name} is bound two times, "
                                     f"once by {hg_name} and once by {ifaces[iface]}")
                ifaces[iface] = hg_name

        return hostgroups

    @pydantic.field_validator("switchgroups")
    @classmethod
    def ensure_switchgroup_id_unique(cls, switchgroups: list[SwitchGroup],) -> list[SwitchGroup]:
        group_ids: dict[int, str] = {}
        for sg in switchgroups:
            if sg.group_id in group_ids:
                raise ValueError(f"SwitchGroup {sg.name} has group id {sg.group_id}, which is already in use "
                                 f"by SwitchGroup {group_ids[sg.group_id]}")
            group_ids[sg.group_id] = sg.name

        return switchgroups

    @pydantic.model_validator(mode="after")
    def check_hostgroup_references(self) -> "DriverConfig":
        # check that referenced switches exist
        # check that hosts referenced by metagroups exist
        # check all hostgroup members belong to the same vlan pool

        # get mapping from switch to vlanpool
        switch_vlanpool_map = {}
        for sg in self.switchgroups:
            for switch in sg.members:
                switch_vlanpool_map[switch.name] = sg.vlan_pool

        all_hosts = set()
        host_vlanpool_map = {}
        for hg in self.hostgroups:
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
        for hg in self.hostgroups:
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

        return self

    @pydantic.model_validator(mode="after")
    def ensure_interconnect_az_requirements(self) -> "DriverConfig":
        """Make sure transits service their own AZ and all others service ONLY their own AZ"""

        for hg in self.hostgroups:
            if hg.role is None:
                continue
            found = False
            for sg in self.switchgroups:
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

        return self

    @pydantic.model_validator(mode="after")
    def ensure_all_switchgroup_azs_exist(self) -> "DriverConfig":
        azs = {az.name for az in self.global_config.availability_zones}

        for sg in self.switchgroups:
            if sg.availability_zone not in azs:
                raise ValueError(f"SwitchGroup {sg.name} has invalid az {sg.availability_zone} - "
                                 f"options are '{', '.join(azs)}'")

        return self

    @pydantic.model_validator(mode="after")
    def ensure_all_infra_network_vrf_exist(self) -> "DriverConfig":
        vrf_names = {vrf.name for vrf in self.global_config.vrfs}
        print("vrf_names", vrf_names)

        for hg in self.hostgroups:
            if hg.infra_networks:
                for net in hg.infra_networks:
                    if net.vrf and net.vrf not in vrf_names:
                        raise ValueError(f'Associated VRF {net.vrf} of infra network {net.name} is not existing')

        return self

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
        return {hg_config.get_availability_zone(self) for hg_config in self.get_hostgroups_by_hosts(binding_hosts)
                if not (ignore_special and hg_config.role)}

    def list_availability_zones(self):
        return sorted(az.name for az in self.global_config.availability_zones)


class Credentials(pydantic.BaseModel):
    user: str
    password: str


class DriverCredentials(pydantic.BaseModel):
    switch_credentials: dict[str, Credentials] | None = None
