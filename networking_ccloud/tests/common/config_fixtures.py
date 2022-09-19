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

from networking_ccloud.common.config import config_driver
from networking_ccloud.common import constants as cc_const


DEFAULT_AZ = "qa-test-1a"


def make_switch(name, platform="test", **kwargs):
    if platform == "test":
        # enable test platform
        config_driver.Switch._allow_test_platform = True
        cc_const.SWITCH_AGENT_TOPIC_MAP['test'] = 'cc-fabric-switch-agent-test'

    switch_vars = dict(
        name=name, platform=platform,
        user="maunzuser", password="maunzpassword",
        host="1.1.1.1", bgp_source_ip="1.1.1.2",  # FIXME: derive IPs from somewhere
    )
    switch_vars.update(kwargs)

    return config_driver.Switch(**switch_vars)


_LAST_AUTO_GROUP_ID = 0


def make_switchgroup(name, members=None, switch_vars=None, availability_zone=DEFAULT_AZ, **kwargs):
    switchgroup_vars = dict(
        name=name, asn=65100, availability_zone=availability_zone, role="vpod",
        vtep_ip="1.1.1.3",  # FIXME: derive IPs from somewhere
    )
    switchgroup_vars.update(kwargs)

    if 'group_id' not in kwargs:
        global _LAST_AUTO_GROUP_ID
        _LAST_AUTO_GROUP_ID += 1
        switchgroup_vars['group_id'] = _LAST_AUTO_GROUP_ID

    if switch_vars is None:
        switch_vars = None
    if members is None:
        members = [dict(name=f"{name}-sw{num}", **switch_vars or {}) for num in (1, 2)]
    for n, member_vars in enumerate(members):
        if isinstance(member_vars, dict):
            members[n] = make_switch(**member_vars)

    return config_driver.SwitchGroup(members=members, **switchgroup_vars)


# create switchports
def gen_switchport_names(switchgroup=None, switches=None, ports_per_switch=2, offset=0):
    if switches is None and switchgroup is not None:
        switches = [f"{switchgroup}-sw1", f"{switchgroup}-sw2"]

    ports = {s: [] for s in switches}
    for port_counter in range(ports_per_switch):
        port_num = 1 + offset + port_counter
        for switch in switches:
            ports[switch].append(f"Ethernet{port_num}")
    return ports


def make_switchport(switch, name, lacp=False, members=None, unmanaged=False):
    return config_driver.SwitchPort(switch=switch, name=name, lacp=lacp, members=members, unmanaged=unmanaged)


def make_lacp(pc_id, switchgroup, **kwargs):
    result = []
    for switch, ports in gen_switchport_names(switchgroup, **kwargs).items():
        port = config_driver.SwitchPort(switch=switch, name=f"Port-Channel{pc_id}", lacp=True, members=ports)
        result.append(port)
    return result


# hostgroups
def make_hostgroups(switchgroup, nodes=10, ports_per_switch=2, offset=0, **kwargs):
    groups = []
    for n in range(1, nodes + 1):
        ports = make_lacp(100 + n, switchgroup, ports_per_switch=ports_per_switch, offset=(n - 1) * ports_per_switch)
        binding_host = f"node{n:03d}-{switchgroup}"
        hg = config_driver.Hostgroup(binding_hosts=[binding_host], members=ports, **kwargs)
        groups.append(hg)
    return groups


def make_metagroup(switchgroup, hg_kwargs={}, meta_kwargs={}):
    groups = make_hostgroups(switchgroup, **hg_kwargs)
    members = [host for group in groups for host in group.binding_hosts]
    hg = config_driver.Hostgroup(binding_hosts=[f"nova-compute-{switchgroup}"], members=members, metagroup=True,
                                 **meta_kwargs)
    groups.append(hg)

    return groups


def make_interconnect(role, host, switch_base, handle_azs):
    unmanaged = role == config_driver.HostgroupRole.transit
    sp_name = f"{host}-1/1/1" if role != config_driver.HostgroupRole.bgw else None
    return config_driver.Hostgroup(binding_hosts=[host], role=role,
                                   members=[make_switchport(f"{switch_base}-sw1", sp_name, unmanaged=unmanaged)],
                                   handle_availability_zones=handle_azs)


def make_global_config(asn_region=65123, **kwargs):
    kwargs.setdefault("default_vlan_ranges", ["2000:3750"])
    kwargs.setdefault("availability_zones", [])
    kwargs.setdefault("vrfs", [])
    return config_driver.GlobalConfig(asn_region=asn_region, **kwargs)


def make_azs(names):
    azs = []
    for name in names:
        az_num = ord(name[-1]) - ord('a') + 1
        azs.append(config_driver.AvailabilityZone(name=name, suffix=name[-1], number=az_num))
    return azs


def make_azs_from_switchgroups(switchgroups):
    if switchgroups is None:
        return []

    return make_azs(az for az in set(sg.availability_zone for sg in switchgroups))


def make_vrfs(names):
    vrfs = []
    for i, name in enumerate(names):
        vrfs.append(config_driver.VRF(name=name, number=i + 1))
    return vrfs


def make_vrfs_from_hostgroups(hostgroups):
    if hostgroups is None:
        return []
    infra_nets = list()
    for hostgroup in hostgroups:
        if hostgroup.infra_networks:
            infra_nets.extend(hostgroup.infra_networks)

    return make_vrfs(set(x.vrf for x in infra_nets if x.vrf))


# whole config
def make_config(switchgroups=None, hostgroups=None, global_config=None):
    if not global_config:
        global_config = make_global_config(availability_zones=make_azs_from_switchgroups(switchgroups),
                                           vrfs=make_vrfs_from_hostgroups(hostgroups))

    return config_driver.DriverConfig(
        switchgroups=switchgroups or [],
        hostgroups=hostgroups or [],
        global_config=global_config
    )
