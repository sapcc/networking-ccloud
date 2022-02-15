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


DEFAULT_AZ = "qa-test-1a"


def make_switch(name, platform="test", **kwargs):
    if platform == "test":
        # enable test platform
        config_driver.Switch._allow_test_platform = True

    switch_vars = dict(
        name=name, platform=platform,
        user="maunzuser", password="maunzpassword",
        host="1.1.1.1", bgp_source_ip="1.1.1.2",  # FIXME: derive IPs from somewhere
    )
    switch_vars.update(kwargs)

    return config_driver.Switch(**switch_vars)


def make_switchgroup(name, members=None, switch_vars=None, **kwargs):
    switchgroup_vars = dict(
        name=name, asn=65100, availability_zone=DEFAULT_AZ, role="vpod",
        vtep_ip="1.1.1.3",  # FIXME: derive IPs from somewhere
    )
    switchgroup_vars.update(kwargs)

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


def make_switchport(switch, name, lacp=False, members=None):
    return config_driver.SwitchPort(switch=switch, name=name, lacp=lacp, members=members)


def make_lacp(pc_id, switchgroup, **kwargs):
    result = []
    for switch, ports in gen_switchport_names(switchgroup, **kwargs).items():
        port = config_driver.SwitchPort(switch=switch, name=f"Port-Channel{pc_id}", lacp=True, members=ports)
        result.append(port)
    return result


# hostgroups
def make_hostgroups(switchgroup, nodes=10, ports_per_switch=2, offset=0):
    groups = []
    for n in range(1, nodes + 1):
        ports = make_lacp(100 + n, switchgroup, ports_per_switch=ports_per_switch, offset=(n - 1) * ports_per_switch)
        binding_host = f"node{n:03d}-{switchgroup}"
        hg = config_driver.Hostgroup(binding_hosts=[binding_host], members=ports)
        groups.append(hg)
    return groups


def make_metagroup(switchgroup, **kwargs):
    groups = make_hostgroups(switchgroup, **kwargs)
    members = [host for group in groups for host in group.binding_hosts]
    hg = config_driver.Hostgroup(binding_hosts=[f"nova-compute-{switchgroup}"], members=members, metagroup=True)
    groups.append(hg)

    return groups


# whole config
def make_config(switchgroups=None, hostgroups=None):
    return config_driver.DriverConfig(switchgroups=switchgroups or [], hostgroups=hostgroups or [])
