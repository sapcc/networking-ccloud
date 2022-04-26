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

import ipaddress
from itertools import groupby
import logging
from operator import itemgetter
import re
import urllib3
from typing import Dict, Optional

import pynetbox
import requests
import yaml

from networking_ccloud.common.config import config_driver as conf
from networking_ccloud.common import constants as c_const

LOG = logging.getLogger(__name__)


class ConfigException(Exception):
    pass


class ConfigSchemeException(ConfigException):
    pass


class ConfigGenerator:
    # FIXME: some of these shall be imported from networking-ccloud constants

    # FIXME: some of these should come from an external config for this tool in the future
    netbox_url = "https://netbox.global.cloud.sap"
    switch_name_re = re.compile(r"^(?P<region>\w{2}-\w{2}-\d)-sw(?P<az>\d)(?P<pod>\d)(?P<switchgroup>\d{2})"
                                r"(?P<leaf>[ab])(?:-(?P<role>[a-z]+(?P<seq_no>[0-9]+)?))$")
    region = "qa-de-2"
    leaf_role = "evpn-leaf"
    spine_role = "evpn-spine"
    connection_roles = {"server", "neutron-router"}
    pod_roles = {
        "cc-apod": c_const.SWITCHGROUP_ROLE_APOD,
        "cc-vpod": c_const.SWITCHGROUP_ROLE_VPOD,
        "cc-stpod": c_const.SWITCHGROUP_ROLE_STPOD,
        "cc-netpod": c_const.SWITCHGROUP_ROLE_NETPOD,
        "cc-bpod": c_const.SWITCHGROUP_ROLE_BPOD,
        "cnd-net-evpn-bg": c_const.DEVICE_TYPE_BGW,
        "cnd-net-evpn-tl": c_const.DEVICE_TYPE_TRANSIT,
        "cnd-net-evpn-bl": c_const.DEVICE_TYPE_BORDER
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
            seq_no=int(m.group('seq_no')) if m.group('seq_no') else 0
        )

    def get_switch_role(self, device) -> str:
        slugs = {x.slug for x in device.tags}
        pod_roles = {self.pod_roles[x] for x in slugs.intersection(self.pod_roles.keys())}
        if len(pod_roles) > 1:
            if pod_roles == {c_const.DEVICE_TYPE_BORDER, c_const.DEVICE_TYPE_TRANSIT}:
                return c_const.DEVICE_TYPE_BORDER_AND_TRANSIT
            raise ConfigSchemeException(f'Device {device.name} should only have 1 pod role but has {pod_roles}')
        if not pod_roles:
            raise ConfigSchemeException(f'Device {device.name} has no pod roles')
        return pod_roles.pop()

    def get_switchgroup_name(self, device_name: str, role: str, pod: int, switchgroup_no: int, leaf_no: int,
                             az_no: int, seq_no: Optional[int], **kwargs):
        if role in {c_const.SWITCHGROUP_ROLE_NETPOD, c_const.SWITCHGROUP_ROLE_APOD, c_const.SWITCHGROUP_ROLE_STPOD,
                    c_const.SWITCHGROUP_ROLE_VPOD, c_const.SWITCHGROUP_ROLE_BPOD}:
            if seq_no == 0:
                raise ConfigSchemeException(f'{device_name} has no seq_no')
            return f'{role}{seq_no:03d}'
        return f"{role}-{az_no}{pod}{switchgroup_no:02d}"

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

    def get_netbox_data(self, region):
        asn_region = self.get_asn_region(region)
        switches = []
        clusters = {}

        leafs = self.netbox.dcim.devices.filter(region=region, role=self.leaf_role, status='active')
        for leaf in leafs:
            switch_name = leaf.name

            # platform check!
            platform = leaf.platform.slug
            if platform not in c_const.PLATFORMS:
                print(f"Warning: Device {switch_name} is of platform {platform}, "
                      "which is not supported by the driver/config generator")
                continue

            # use nb primary address for now, later this is probably going to be loopback10
            if not leaf.primary_ip:
                raise ConfigSchemeException(f"Device {leaf.name} does not have a usable primary address")
            host_ip = leaf.primary_ip.address.split("/")[0]

            numbered_resources = self.parse_ccloud_switch_number_resources(switch_name)
            role = self.get_switch_role(leaf)

            switch = {
                'name': switch_name,
                'ports': dict(),
                'hosts': dict(),
                'platform': platform,
                'role': role,
                'az': leaf.site.name,
                'switchgroup': self.get_switchgroup_name(switch_name, role, **numbered_resources),
                'host': host_ip
            }
            switch.update(**self.get_l3_data(asn_region, **numbered_resources))

            switches.append(switch)

            ifaces = self.netbox.dcim.interfaces.filter(device_id=leaf.id, connection_status=True)
            for iface in ifaces:
                # FIXME: ignore management, peerlink (maybe), unconnected ports
                if iface.connected_endpoint is None:
                    continue

                far_device = iface.connected_endpoint.device
                if far_device.device_role.slug not in self.connection_roles:
                    continue

                if self.verbose:
                    print(f"Device {switch_name} port {iface.name} is connected to "
                          f"device {far_device.name} port {iface.connected_endpoint.name} "
                          f"role {far_device.device_role.name}")

                switch['hosts'].setdefault(far_device.name, []).append(iface.name)

                # cluster mgmt for far hosts
                if far_device.cluster:
                    cluster = far_device.cluster
                    cname = cluster.name
                    if cname not in clusters:
                        binding_host = None
                        cluster_type = cluster.type.slug
                        # figure out cluster name
                        if cluster_type == self.netbox_vpod_cluster_type:
                            # FIXME: CCloud specific name generation
                            if not cname.startswith("production"):
                                print(f"Warning: Cluster {cname} of type {cluster_type} does not start "
                                      "with 'production' - ignoring")
                                continue
                            binding_host = "nova-compute-{}".format(cname[len("production"):])
                        else:
                            print(f"Warning: Cluster {cname} has unknown cluster type {cluster_type} - ignoring")
                            continue
                        # create cluster
                        clusters[cname] = {
                            'id': cluster.id,
                            'type': cluster.type.slug,
                            'members': set(),
                            'binding_host': binding_host,
                        }
                    else:
                        # check if same cluster
                        if clusters[cname]['id'] != cluster.id:
                            raise ConfigException(f"Found two clustergroups with name {cname}, but different ids "
                                                  f"({clusters[cname]['id']} vs {cluster.id}) - this needs to be "
                                                  "resolved before we can generate a proper config")

                    clusters[cname]['members'].add(far_device.name)

        data = {
            'switches': switches,
            'clusters': clusters,
            'asn_region': asn_region,
        }

        return data

    def generate_switch_config(self):
        config = {
            'switches': [],
            'switchgroups': [],
            'hostgroups': [],
        }

        nb_data = self.get_netbox_data(self.region)
        nb_switches = nb_data['switches']

        def _get_single(item_set, item_name, switchgroup):
            if not item_set:
                raise ConfigException(f"Switchgroup {switchgroup} has no entry for {item_name}")
            if len(item_set) > 1:
                raise ConfigException(f"Inconsistent {item_name} found for switchgroup {switchgroup}: {item_set}")
            return item_set.pop()

        # build switchgroups (sorted by switchgroup.name, switch.name)
        switchgroups = []
        sorted_nb_switches = sorted(nb_switches, key=itemgetter('switchgroup', 'name'))
        for groupname, nb_switchgroup in groupby(sorted_nb_switches, key=itemgetter('switchgroup')):
            switches = []
            az = set()
            role = set()
            loopback1 = set()
            asn = set()
            nb_switchgroup = list(nb_switchgroup)
            for nb_switch in sorted(nb_switchgroup, key=itemgetter('name')):
                az.add(nb_switch['az'])
                role.add(nb_switch['role'])
                loopback1.add(nb_switch['loopback1'])
                asn.add(nb_switch['asn'])
                switch = conf.Switch(name=nb_switch['name'], host=nb_switch['host'],
                                     bgp_source_ip=nb_switch['loopback0'], platform=nb_switch['platform'],
                                     user=self.args.switch_user, password=self.args.switch_password)

                switches.append(switch)
            az = _get_single(az, "AZ", groupname)
            role = _get_single(role, "role", groupname)
            loopback1 = _get_single(loopback1, "loopback1", groupname)
            asn = _get_single(asn, "asn", groupname)
            switchgroup = conf.SwitchGroup(name=groupname, members=switches, availability_zone=az, role=role,
                                           vtep_ip=loopback1, asn=asn)
            switchgroups.append(switchgroup)

        # build hostgroups (sorted by switchgroup, meta, groupname)
        hg_map = {}
        for nb_switch in nb_switches:
            # FIXME: meta hostgroup based on roles
            for host, ports in nb_switch['hosts'].items():
                hg = hg_map.setdefault(host, dict(ports=[], switchgroups=[]))
                for port in ports:
                    hg['ports'].append((nb_switch['name'], port))
                    hg['switchgroups'].append(nb_switch['switchgroup'])

        hostgroups = []
        for hg_name, data in sorted(hg_map.items(), key=lambda x: (x[1]['switchgroups'][0], x[0])):
            # build switchports (sort by port, switch)
            switchports = []
            for switch, port in sorted(data['ports'], key=itemgetter(1, 0)):
                sp = conf.SwitchPort(switch=switch, name=port)
                switchports.append(sp)
            hg = conf.Hostgroup(binding_hosts=[hg_name], members=switchports)
            hostgroups.append(hg)

        # FIXME: meta hostgroups based on device-role
        # FIXME: check that no hostgroup has switches from two different switchgroups
        nb_clusters = nb_data['clusters']
        print(nb_clusters)

        for cluster in nb_clusters.values():
            print(cluster)
            hg = conf.Hostgroup(binding_hosts=[cluster['binding_host']], metagroup=True,
                                members=list(cluster['members']))
            hostgroups.append(hg)

        # FIXME: sort hostgroups

        # build global config
        global_config = conf.GlobalConfig(asn_region=nb_data['asn_region'])

        # build top config object
        config = conf.DriverConfig(global_config=global_config, switchgroups=switchgroups, hostgroups=hostgroups)

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
    cfg = cfggen.generate_switch_config()

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
