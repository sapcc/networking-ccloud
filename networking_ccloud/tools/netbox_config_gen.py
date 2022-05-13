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

from collections import defaultdict, Counter
import ipaddress
from itertools import groupby
import logging
from operator import itemgetter
import re
import urllib3
from typing import Any, Dict, Optional, List, Tuple, Set, Iterable

import pynetbox
from pynetbox.core.response import Record as NbRecord
import requests
import yaml

from networking_ccloud.common.config import config_driver as conf
from networking_ccloud.common import constants as c_const

LOG = logging.getLogger(__name__)

SWITCHGROUP_ROLE_VPOD = 'vpod'
SWITCHGROUP_ROLE_STPOD = 'stpod'
SWITCHGROUP_ROLE_APOD = 'apod'
SWITCHGROUP_ROLE_NETPOD = 'netpod'
SWITCHGROUP_ROLE_BPOD = 'bpod'


class ConfigException(Exception):
    pass


class ConfigSchemeException(ConfigException):
    pass


class ConfigGenerator:
    # FIXME: some of these shall be imported from networking-ccloud constants

    # FIXME: some of these should come from an external config for this tool in the future
    netbox_url = "https://netbox.global.cloud.sap"
    switch_name_re = re.compile(r"^(?P<region>\w{2}-\w{2}-\d)-sw(?P<switchgroup_id>(?P<az>\d)"
                                r"(?P<pod>\d)(?P<switchgroup>\d{2}))"
                                r"(?P<leaf>[ab])(?:-(?P<role>[a-z]+(?P<seq_no>[0-9]+)?))$")
    region = "qa-de-2"
    leaf_role = "evpn-leaf"
    spine_role = "evpn-spine"
    connection_roles = {"server", "neutron-router"}
    pod_roles = {
        "cc-apod": SWITCHGROUP_ROLE_APOD,
        "cc-vpod": SWITCHGROUP_ROLE_VPOD,
        "cc-stpod": SWITCHGROUP_ROLE_STPOD,
        "cc-netpod": SWITCHGROUP_ROLE_NETPOD,
        "cc-bpod": SWITCHGROUP_ROLE_BPOD,
        "cnd-net-evpn-bg": c_const.DEVICE_TYPE_BGW,
        "cnd-net-evpn-tl": c_const.DEVICE_TYPE_TRANSIT,
    }
    netbox_vpod_cluster_type = "cc-vsphere-prod"

    def __init__(self, region, args, verbose=False, verify_ssl=False):
        self.region = region
        self.args = args
        self.verbose = verbose

        self.netbox = pynetbox.api(self.netbox_url)
        if not verify_ssl:
            urllib3.disable_warnings()
            self.netbox.http_session = requests.Session()
            self.netbox.http_session.verify = False

    def _ensure_single_item(self, item_set: Iterable[Any], entity: str, identifier: str, attribute: str) -> Any:
        if not isinstance(item_set, set):
            item_set = set(item_set)
        if len(item_set) != 1:
            raise ConfigSchemeException(f'{entity} identified by {identifier}: '
                                        f'Unexpected values for {attribute}, expected 1 but got {len(item_set)}')
        return item_set.pop()

    def parse_ccloud_switch_number_resources(self, device_name: str) -> Dict[str, int]:
        """Parse switch number resources specific to CCloud naming scheme

        Should return pod, switchgroup, leaf_no, az_no
        """

        m = self.switch_name_re.match(device_name)

        if not m:
            raise ConfigSchemeException(f"Could not match '{device_name}' to CCloud hostname scheme "
                                        "(e.g. qa-de-1-sw1234a-bb123)")
        return dict(
            pod=int(m.group("pod")),
            switchgroup_no=int(m.group("switchgroup")),
            # leaf number is calculated by enumerating the leaf chars
            leaf_no=ord(m.group("leaf")) - ord("a") + 1,
            az_no=int(m.group('az')),
            seq_no=int(m.group('seq_no')) if m.group('seq_no') else 0,
            switchgroup_id=int(m.group('switchgroup_id'))
        )

    def get_switchgroup_attributes(self, devices: List[NbRecord]) -> Dict[str, str]:

        attributes = dict()
        pod_roles = set()
        azs = set()

        for device in devices:

            # roles
            if device.tags:
                pod_roles = set(filter(lambda x: x,  (self.pod_roles.get(x.slug, None) for x in device.tags)))

            # azs
            if not device.site:
                raise ConfigException(f'{device.name} must have a site')
            azs.add(device.site.slug)

        # silently reject switches without a role, could be BL or anything we do not care about
        if not pod_roles:
            return dict()

        attributes['pod_role'] = self._ensure_single_item(pod_roles, 'Switchgroup',
                                                          ', '.join((x.name for x in devices)), 'pod_roles')
        attributes['az'] = self._ensure_single_item(azs, 'Switchgroup',
                                                    ', '.join((x.name for x in devices)), 'azs')

        return attributes

    def get_switchgroup_name(self, role: str, switchgroup_id: int):
        return f"{role}-{switchgroup_id:04d}"

    def get_l3_data(self, asn_region: int, pod: int, switchgroup_no: int, leaf_no: int,
                    az_no: int, **kwargs) -> Dict[str, str]:
        return dict(
            loopback0=str(ipaddress.ip_address(f"{az_no}.{pod}.{switchgroup_no}.{leaf_no}")),
            loopback1=str(ipaddress.ip_address(f"{az_no}.{pod}.{switchgroup_no}.0")),
            asn=f"{asn_region}.{az_no}{pod}{switchgroup_no:02d}"
        )

    def get_asn_region(self, region):
        sites = self.netbox.dcim.sites.filter(region=region)
        site_asns = {site.asn for site in sites if site.asn}
        if not site_asns:
            raise ConfigException(f"Region {region} has no ASN")
        if len(site_asns) > 1:
            raise ConfigException(f"Region {region} has multiple ASNs: {site_asns}")
        return site_asns.pop()

    def make_switch(self, asn_region: int, switch: NbRecord, user: str, password: str) -> Optional[conf.Switch]:

        # platform check!
        platform = getattr(switch.platform, 'slug', None)
        if platform not in c_const.PLATFORMS:
            print(f"Warning: Device {switch.name} is of platform {platform}, "
                  "which is not supported by the driver/config generator")
            return None

        # use nb primary address for now, later this is probably going to be loopback10
        if not switch.primary_ip:
            raise ConfigSchemeException(f"Device {switch.name} does not have a usable primary address")
        host_ip = switch.primary_ip.address.split("/")[0]

        numbered_resources = self.parse_ccloud_switch_number_resources(switch.name)
        l3_data = self.get_l3_data(asn_region, **numbered_resources)

        return conf.Switch(
            name=switch.name,
            host=host_ip,
            platform=platform,
            bgp_source_ip=l3_data['loopback0'],
            user=user,
            password=password)

    def get_switchgroups(self, asn_region: int, switches: List[NbRecord],
                         switch_user: str, switch_password: str) -> List[conf.SwitchGroup]:
        switchgroups = list()
        # use a tuple of all the numbered resources to group by
        sorter = lambda x: self.parse_ccloud_switch_number_resources(x.name)['switchgroup_id']  # noqa: E731
        sorted_switches = sorted(switches, key=sorter)
        for switchgroup_id, group_switches in groupby(sorted_switches, key=sorter):
            group_switches = sorted(group_switches, key=itemgetter('name'))
            sg_attributes = self.get_switchgroup_attributes(group_switches)
            if not sg_attributes:
                continue
            members = []
            for switch in group_switches:
                conf_switch = self.make_switch(asn_region, switch, switch_user, switch_password)
                if conf_switch:
                    members.append(conf_switch)
            if len(members) < 2:
                raise ValueError(f'Switchgroup {switchgroup_id} has only 1 member')
            # FIXME: Warn when a switchgroup is larger 2
            # we derive loopback1/asn from switch_number_resources which we already grouped on
            # so a switchgroup is guranteed to have the same values
            numbered_resources = self.parse_ccloud_switch_number_resources(members[0].name)
            l3_data = self.get_l3_data(asn_region, **numbered_resources)
            sg_name = self.get_switchgroup_name(sg_attributes['pod_role'], numbered_resources['switchgroup_id'])
            switchgroup = conf.SwitchGroup(name=sg_name, members=members, availability_zone=sg_attributes['az'],
                                           vtep_ip=l3_data['loopback1'], asn=l3_data['asn'])
            switchgroups.append(switchgroup)
        return switchgroups

    def get_connected_devices(self, switches: List[NbRecord]) -> Tuple[Set[NbRecord], List[conf.Hostgroup]]:
        device_ports_map: Dict[NbRecord, List[conf.SwitchPort]] = defaultdict(list)
        for switch in switches:
            ifaces = self.netbox.dcim.interfaces.filter(device_id=switch.id, connection_status=True)
            for iface in ifaces:
                # FIXME: ignore management, peerlink (maybe), unconnected ports
                if iface.connected_endpoint is None:
                    continue

                far_device = iface.connected_endpoint.device
                if far_device.device_role.slug not in self.connection_roles:
                    continue

                if self.verbose:
                    print(f"Device {switch.name} port {iface.name} is connected to "
                          f"device {far_device.name} port {iface.connected_endpoint.name} "
                          f"role {far_device.device_role.name}")

                if iface.lag is not None:
                    # We fill this list only if this filter comes back False, so this is assumed to be unique
                    lags = filter(lambda x: x.switch == switch.name and x.name == iface.lag.name and x.lacp,
                                  device_ports_map.get(far_device.name, []))
                    lag: Optional[conf.SwitchPort] = next(lags, None)
                    if lag:
                        lag.members.append(iface.name)
                    else:
                        device_ports_map[far_device].append(conf.SwitchPort(switch=switch.name, lacp=True,
                                                                            name=iface.lag.name, members=[iface.name]))
                else:
                    # not a lag
                    device_ports_map[far_device].append(conf.SwitchPort(switch=switch.name, name=iface.name))
        hgs = [conf.Hostgroup(binding_hosts=[h.name], direct_binding=True, members=m)
               for h, m in device_ports_map.items()]
        return set(device_ports_map.keys()), hgs

    def cluster_is_valid(self, cluster) -> bool:
        if not cluster.name:
            print(f'Warning: Cluster {cluster.id} has no name - ignoring')
            return False
        if not cluster.type:
            print(f'Warning: Cluster {cluster.name} has no type - ignoring')
            return False
        if cluster.type.slug not in {self.netbox_vpod_cluster_type}:
            print(f'Warning: Cluster {cluster.name} has unsupported type {cluster.type.slug} - ignoring')
            return False
        return True

    def make_vpod_metagroup(self, cluster: NbRecord, member: NbRecord) -> Optional[conf.Hostgroup]:
        # FIXME: CCloud specific name generation
        cname: str = cluster.name  # type: ignore
        ctype = cluster.type.slug  # type: ignore
        if not cname.startswith("production"):
            print(f"Warning: Cluster {cname} of type {ctype} does not start "
                  "with 'production' - ignoring")
            return None
        binding_host = "nova-compute-{}".format(cname[len("production"):])
        return conf.Hostgroup(binding_hosts=[binding_host], metagroup=True, members=[member.name])

    def get_metagroups(self, connected_devices: Set[NbRecord]) -> List[conf.Hostgroup]:
        metagroups: Dict[NbRecord, conf.Hostgroup] = dict()
        for device in connected_devices:
            if not device.cluster:
                continue
            cluster = device.cluster
            if not self.cluster_is_valid(cluster):
                continue
            metagroup = metagroups.get(cluster, None)
            if not metagroup:
                # create the metagroup
                if getattr(cluster.type, 'slug', None) == self.netbox_vpod_cluster_type:
                    metagroup = self.make_vpod_metagroup(cluster, device)
                if not metagroup:
                    # something failed here, so we ignore
                    continue
                metagroups[cluster] = metagroup
            else:
                metagroup.members.append(device.name)

        # Check cluster names for duplicates
        cluster_names = (x.name for x in metagroups.keys())
        for name, count in Counter(cluster_names).items():
            if count > 1:
                raise ConfigException(f'Cluster {name} appeared {count} times')
        return list(metagroups.values())

    def generate_config(self):

        switch_user = self.args.switch_user
        switch_password = self.args.switch_password

        nb_switches = list(self.netbox.dcim.devices.filter(region=self.region, role=self.leaf_role, status='active'))
        asn_region = self.get_asn_region(self.region)
        switchgroups = self.get_switchgroups(asn_region, nb_switches, switch_user, switch_password)
        connected_devices, direct_hgs = self.get_connected_devices(nb_switches)
        metagroups = self.get_metagroups(connected_devices)

        binding_host_hg_map = {hg.binding_hosts[0]: hg for hg in direct_hgs}

        global_config = conf.GlobalConfig(asn_region=asn_region)

        # FIXME: meta hostgroups based on device-role
        # FIXME: check that no hostgroup has switches from two different switchgroups
        binding_hosts_in_metagroup = set()
        hostgroups = list()
        for metagroup in metagroups:
            for member in sorted(metagroup.members):  # type: ignore
                direct_binding_host = binding_host_hg_map.get(member)  # type: ignore
                if direct_binding_host:
                    hostgroups.append(direct_binding_host)
                    binding_hosts_in_metagroup.add(direct_binding_host.binding_hosts[0])
                    # FIXME: Host in multiple metagroups
                    # FIXME: Host does not exist
            hostgroups.append(metagroup)

        missing_hosts = binding_host_hg_map.keys() - binding_hosts_in_metagroup
        for host in missing_hosts:
            hostgroups.append(binding_host_hg_map[host])

        # build global config
        global_config = conf.GlobalConfig(asn_region=nb_data['asn_region'])

        config = conf.DriverConfig(global_config=global_config, switchgroups=switchgroups,
                                   hostgroups=hostgroups)

        return config

    def do_sanity_check(self, config):
        # FIXME: after config has been created, load it with the normal driver verification stuff
        pass


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--region", required=True)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-u", "--switch-user", help="Default switch user", required=True)
    parser.add_argument("-p", "--switch-password", help="Default switch password", required=True)
    parser.add_argument("-s", "--shell", action="store_true")
    parser.add_argument("-o", "--output")

    args = parser.parse_args()

    cfggen = ConfigGenerator(args.region, args, args.verbose)
    cfg = cfggen.generate_config()

    from pprint import pprint
    pprint(cfg)

    if args.output:
        conf_data = cfg.dict(exclude_unset=True)
        yaml_data = yaml.safe_dump(conf_data)
        if args.output == '-':
            print(yaml_data)
        else:
            with open(args.output, "w") as f:
                f.write(yaml_data)

    if args.shell:
        import IPython
        IPython.embed()


if __name__ == '__main__':
    main()
