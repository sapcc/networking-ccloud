# Copyright 2026 SAP SE
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

from collections import defaultdict
import ipaddress
from itertools import groupby
import logging
from operator import attrgetter
from pathlib import Path
import re
import sys
import time
import urllib3

from munch import Munch
import pynetbox
import requests
import yaml

from networking_ccloud.common.config import config_driver as conf
from networking_ccloud.common import constants as c_const

LOG = logging.getLogger(__name__)

SWITCHGROUP_ROLE_VPOD = 'bb'
SWITCHGROUP_ROLE_STPOD = 'st'
SWITCHGROUP_ROLE_APOD = 'ap'
SWITCHGROUP_ROLE_NETPOD = 'np'

RESPONSIBLE_LAG_RANGE = range(101, 200)
DEFAULT_VLAN_RANGES = ["2000:3750"]
NETWORK_AGENTS_PER_APOD = 15

VAULT_REF_REPLACEMENT = 'VAULTER-WHITE-REPLACE-ME'


class ConfigException(Exception):
    pass


class ConfigSchemeException(ConfigException):
    pass


NB_GRAPHQL_SWITCH_INFO = """
query($device_id: ID!) {
  device(id: $device_id) {
    id
    name
    # FIXME: is occupied what we want or is it connected?
    interfaces(filters: {occupied: true}) {
      id
      name
      tags {
        slug
      }
      lag {
        id
        name
        tags {
          slug
        }
      }
      device {
        name
        platform {
          slug
        }
      }
      connected_endpoints {
        ... on InterfaceType {
          name
          lag {
            name
          }
          tagged_vlans {
            vid
            name
            group {
              slug
            }
            tags {
              slug
            }
          }
          device {
            id
            name
            # FIXME: parent_device is missing
            role {
              name
              slug
            }
            tenant {
              slug
            }
            cluster {
              name
              type {
                slug
              }
              devices {
                id
                name
              }
            }
          }
        }
      }
    }
  }
}
"""


NB_GRAPHQL_SWITCH_LIST = """
query QueryDeviceList($region: String!, $role: String!) {
  device_list(filters: {region: [$region], role: [$role], status: "active"}) {
    id
    name
    platform {
      slug
    }
    site {
      slug
    }
    role {
      name
    }
    tags {
      slug
    }
    config_context
    interfaces(filters: {name: {exact: "Loopback10"}}) {
      name
      ip_addresses {
        display
      }
    }
  }
}
"""


NB_GRAPHQL_REGION_SITE_LIST = """
query QueryRegionSites($region: String!) {
  region_list(filters: {name: {i_exact: $region}}) {
    name
    sites {
      name
      slug
      custom_fields
    }
  }
}
"""


NB_GRAPHQL_VRF_LIST = """
query QueryVRFs($vrf_prefix_1: String!, $vrf_prefix_2: String!) {
  vrf_list(filters: {name: {starts_with: $vrf_prefix_1}, OR: {name: {starts_with: $vrf_prefix_2}}}) {
    id
    name
    rd
    tenant {
      slug
    }
  }
}
"""


class NetboxDataSource:
    netbox_url = "https://netbox.global.cloud.sap"
    switch_name_re = re.compile(r"^(?P<region>\w{2}-\w{2}-\d)-sw(?P<switchgroup_id>(?P<az>\d)"
                                r"(?P<pod>\d)(?P<switchgroup>\d{2}))"
                                r"(?P<leaf>[ab])(?:-(?P<role>[a-z]+(?P<seq_no>[0-9]+)?))$")
    lag_id_re = re.compile(r"^\S+?(?P<lag_id>\d+)$")
    apod_node_name_re = re.compile(r'^node\d+-ap(?P<apod_seq>\d+)$')
    filer_parent_name_re = re.compile(r'^stnpca(?P<cluster_seq>\d+)-st(?P<stpod_seq>\d+)$')
    loadbalancer_vm_name_re = re.compile(
        r'^(?P<region>\w{2}-\w{2}-\d)-(?P<cluster_name>lb\d{3})(?P<ha_role>[a|b])-(?P<seq>\d{2})$')

    LEAF_ROLE = "evpn-leaf"
    use_ebgp = False
    connection_roles = {"server", "neutron-router", "filer", 'loadbalancer', 'dp-data-domain'}
    manila_tag = "manila"
    infra_network_vrf = 'CC-MGMT'
    tenants = {"sap-cloud-infrastructure"}
    pod_roles = {
        "cc-apod": SWITCHGROUP_ROLE_APOD,
        "cc-vpod": SWITCHGROUP_ROLE_VPOD,
        "cc-stpod": SWITCHGROUP_ROLE_STPOD,
        "cc-netpod": SWITCHGROUP_ROLE_NETPOD,
        "cnd-net-evpn-bg": c_const.DEVICE_TYPE_BGW,
        "cnd-net-evpn-tl": c_const.DEVICE_TYPE_TRANSIT,
    }
    ignore_tags = {"cc-net-driver-ignore"}
    extra_vlan_tag = "cc-net-driver-extra-vlan"
    force_speed_tag = 'cc-net-driver-force-speed'
    speed_tag_re = re.compile(r'^cnd-net-portspeed-(?P<speed>\d+g)$')
    lag_member_speed_cache: dict[int, str] = {}

    NETBOX_BGW_TAG = 'cnd-net-evpn-bg'

    def __init__(self):
        self._setup_netbox(verify_ssl=True)
        self.netbox_stats = {'time': 0.0, 'kb': 0.0}

    def _setup_netbox(self, verify_ssl):
        self.netbox = pynetbox.api(self.netbox_url, threading=True)
        if not verify_ssl:
            urllib3.disable_warnings()
            self.netbox.http_session = requests.Session()
            self.netbox.http_session.verify = False

    def query_netbox_graphql(self, query: str, **kwargs: str) -> Munch:
        LOG.debug("graphql query start %s", query.strip().splitlines()[0])
        start_time = time.time()
        resp = self.netbox.http_session.post(f"{self.netbox_url}/graphql/",
                                             json={"query": query, "variables": kwargs})
        resp.raise_for_status()
        LOG.debug("graphql query end took %.2fs for %.02fkb", time.time() - start_time, len(resp.text) / 1024)
        self.netbox_stats['time'] += time.time() - start_time
        self.netbox_stats['kb'] += len(resp.text) / 1024
        return Munch.fromDict(resp.json()["data"])  # pyrefly: ignore[bad-return]

    @staticmethod
    def get_tags(item: Munch) -> list[str]:
        """Get tag slugs from an item"""
        return [tag.slug for tag in item.tags]

    @staticmethod
    def has_any_tag(item: Munch, tag_slugs: list[str] | set[str]) -> bool:
        """Check if the items has any of the provided tags"""
        return any(tag.slug == tag_slug for tag in item.tags for tag_slug in tag_slugs)

    def generate_config(self, region: str, vrf_to_address_scopes_map: dict[str, list[str]],
                        limit_switches: list[str] | None = None) -> conf.DriverConfig:
        """Generate the whole driver config"""

        # FIXME: credentials

        # fetch all switches that are relevant for us
        nb_switches = self.get_switch_list(region, limit_switches)
        asn_region = self.get_region_asn(region)
        switchgroups = self.make_switchgroups(nb_switches, asn_region, None, None)

        # FIXME: sort?
        hostgroups = self.make_hostgroups(nb_switches)

        global_config = self.make_global_config(region, asn_region, vrf_to_address_scopes_map)
        config = conf.DriverConfig(global_config=global_config, switchgroups=switchgroups,
                                   hostgroups=hostgroups)

        LOG.debug("Netbox stats: Took %0.2fs and fetched %0.2fkb data",
                  self.netbox_stats['time'], self.netbox_stats['kb'])

        return config

    def get_switch_list(self, region: str, limit_switches: list[str] | None = None) -> list[Munch]:
        """Get a list of evpn switches from NetBox"""
        nb_switches = self.query_netbox_graphql(NB_GRAPHQL_SWITCH_LIST, region=region, role=self.LEAF_ROLE)
        switches = []
        for switch in nb_switches.device_list:
            if limit_switches and not any(ls in switch.name for ls in limit_switches):
                LOG.debug("Skipping switch %s, excluded by --limit-switches", switch.name)
                continue

            LOG.debug("Processing switch %s (%s)", switch.name, switch.id)

            # check if this switch is usable for us
            if self.has_any_tag(switch, self.ignore_tags):
                continue

            if not self.has_any_tag(switch, list(self.pod_roles)):
                continue

            if (switch_platform := getattr(switch.platform, 'slug', None)) not in c_const.PLATFORMS:
                LOG.warning("Skipping switch %s due to unsupported platform %s", switch.name, switch_platform)
                continue
            LOG.debug(" --> Switch %s added", switch.name)

            switches.append(switch)
        return switches

    def get_connected_devices(self, nb_switches: list[Munch]) -> dict[int, Munch]:
        devices = {}
        for nb_switch in nb_switches:
            LOG.debug("Examining device %s", nb_switch.name)
            nb_switch_detail = self.query_netbox_graphql(NB_GRAPHQL_SWITCH_INFO, device_id=nb_switch.id).device
            for iface in nb_switch_detail.interfaces:
                if self.has_any_tag(iface, self.ignore_tags):
                    continue
                if not iface.lag or not iface.connected_endpoints:
                    continue
                if not (m := self.lag_id_re.match(iface.lag.name)):
                    LOG.warning("Switch %s interface %s has invalid lag name %s",
                                nb_switch.name, iface.name, iface.lag.name)
                    continue
                lag_id = int(m['lag_id'])
                if lag_id not in RESPONSIBLE_LAG_RANGE:
                    LOG.debug("Switch %s interface %s has lag id %s which we are not responsible for",
                              nb_switch.name, iface.name, lag_id)
                    continue

                far_interface = iface.connected_endpoints[0]
                far_device = far_interface.device
                if far_device.role.slug not in self.connection_roles:
                    # FIXME: what role is this for a device?
                    LOG.debug(" ??? Ignoring switch %s interface %s device %s with unusable role %s",
                              nb_switch.name, iface.name, far_device.name, far_device.role.slug)
                    continue
                if far_device.tenant.slug not in self.tenants:
                    LOG.debug(" ??? Ignoring switch %s interface %s device %s with unusable tenant %s",
                              nb_switch.name, iface.name, far_device.name, far_device.tenant.slug)
                    continue
                LOG.debug(" +++ Found device %s on %s/%s", far_device.name, nb_switch.name, iface.name)
                # FIXME: additional filer filtering for parent device in original generator

                if not far_device.cluster:
                    LOG.debug(" ??? --> Ignoring switch %s interface %s device %s with missing cluster config",
                              nb_switch.name, iface.name, far_device.name)
                    continue
                # FIXME: if we don't have a handler for far_device.cluster.type.slug - do we need to handle that here
                #        or is later okay?

                if far_device.id not in devices:
                    devices[far_device.id] = Munch(
                        device=far_device,
                        ifaces=[],
                    )
                iface = Munch(switch=iface.device.name, switch_platform=iface.device.platform.slug,
                              name=iface.name, lag=iface.lag.name, lag_id=lag_id)
                devices[far_device.id].ifaces.append(iface)

        return devices

    def make_hostgroups(self, nb_switches: list[Munch]) -> list[conf.Hostgroup]:
        cluster_hgs = self.make_cluster_hostgroups(nb_switches)
        interconnect_hgs = self.make_interconnection_hostgroups(nb_switches)
        return cluster_hgs + interconnect_hgs

    def make_cluster_hostgroups(self, nb_switches: list[Munch]) -> list[conf.Hostgroup]:
        # okay, hostgroup time! we want to see what our connected switches have!
        # we support
        #   apods?
        #   vpods?
        #   stpods?
        #   bgws?
        def gen_device_bindings_for_cluster(cluster: Munch, direct_binding: bool) -> list[conf.Hostgroup]:
            # FIXME: make this a method or put it somewhere else where it is less disturbing
            direct_groups = []
            for device in cluster.devices:
                if device.id not in conn_info_by_device_id:
                    raise ConfigSchemeException(f"Cluster {cluster.name} device {device.name} id {device.id} is not "
                                                "connected to any device")
                conn_info = conn_info_by_device_id[device.id]

                # create ifaces
                def switch_iface_key(iface: Munch) -> tuple[str, str | None]:
                    return (iface.switch, iface.get('lag'))
                members = []
                conn_info.ifaces.sort(key=switch_iface_key)
                for (switch_name, lag), ifaces in groupby(conn_info.ifaces, key=switch_iface_key):
                    ifaces = list(ifaces)
                    # NOTE(seba): we don't handle interface speeds here at the moment
                    # FIXME: what about unmanaged flag?
                    if lag:
                        if ifaces[0].switch_platform == 'cisco-nx-os':
                            lag_name = f"po{ifaces[0].lag_id}"
                        else:
                            lag_name = ifaces[0].lag

                        lag_members = [iface.name for iface in ifaces]
                        members.append(conf.SwitchPort(
                            switch=switch_name, name=lag_name,
                            lacp=True, members=lag_members,
                        ))

                    else:
                        # these are separate ifaces
                        for iface in ifaces:
                            members.append(conf.SwitchPort(switch=iface.switch, name=iface.name))
                        continue

                hg = conf.Hostgroup(
                    binding_hosts=[conn_info.device.name],
                    direct_binding=direct_binding,
                    members=members,
                )
                direct_groups.append(hg)

            return direct_groups

        hostgroups = []
        connected_devices = self.get_connected_devices(nb_switches)
        conn_info_by_device_id = {conn_info.device.id: conn_info for conn_info in connected_devices.values()}
        seen_clusters = set()
        for conn_info in connected_devices.values():
            cluster = conn_info.device.cluster
            if cluster.name in seen_clusters:
                # we already added this cluster and all dependant devices
                continue
            seen_clusters.add(cluster.name)

            match cluster.type.slug:
                case "cc-kvm-compute":
                    # create one non-direct binding group for each device in cluster
                    new_hgs = gen_device_bindings_for_cluster(cluster, direct_binding=False)
                    hostgroups.extend(new_hgs)
                case "neutron-router-pair":
                    # cluster name example: qa-de-1-asr1k-agent-05
                    m = re.match(r"^\w{2}-\w{2}-\d-(?P<name>asr1k-agent-\d+)$", cluster.name)
                    if not m:
                        raise ConfigSchemeException(f"Device {conn_info.device.name} with cluster type "
                                                    f"{cluster.type.slug} has invalid cluster name {cluster.name}")

                    binding_host = m['name']
                    LOG.info("CLUSTER CREATE host %s --> %s", binding_host, cluster)
                    hg = conf.Hostgroup(
                        binding_hosts=[binding_host],
                        metagroup=True,
                        members=[d.name for d in cluster.devices],
                    )

                    hostgroups.append(hg)
                    hostgroups.extend(gen_device_bindings_for_cluster(cluster, direct_binding=True))
                case _:
                    LOG.warning("Cluster type %s for device %s unhandled",
                                cluster.type.slug, conn_info.device.name)

        return hostgroups

    def make_interconnection_hostgroups(self, nb_switches: list[Munch]) -> list[conf.Hostgroup]:
        bgws: dict[int, conf.Hostgroup] = {}
        for nb_switch in nb_switches:
            if not self.has_any_tag(nb_switch, [self.NETBOX_BGW_TAG]):
                continue
            numbered_resources = self.parse_ccloud_switch_number_resources(nb_switch.name)
            sg_id = numbered_resources['switchgroup_id']
            switchport = conf.SwitchPort(switch=nb_switch.name, name=None)
            if sg_id not in bgws:
                hg = conf.Hostgroup(
                    binding_hosts=[f'{c_const.DEVICE_TYPE_BGW}{sg_id}'],
                    handle_availability_zones=[getattr(nb_switch.site, 'slug', None)],
                    role=c_const.DEVICE_TYPE_BGW, members=[switchport],
                )
                LOG.debug(" +++ Adding hostgroup for bordergateway %s", hg.binding_hosts[0])
                bgws[sg_id] = hg
            else:
                bgws[sg_id].members.append(switchport)

        return list(bgws.values())

    def make_global_config(self, region: str, asn_region: int,
                           vrf_to_address_scopes_map: dict[str, list[str]]) -> conf.GlobalConfig:
        vrfs = self.make_cloud_vrfs(vrf_to_address_scopes_map)
        azs = self.make_azs(region)
        global_config = conf.GlobalConfig(asn_region=asn_region, default_vlan_ranges=DEFAULT_VLAN_RANGES,
                                          vrfs=vrfs, availability_zones=azs)
        return global_config

    def make_cloud_vrfs(self, vrf_to_address_scopes_map: dict[str, list[str]]) -> list[conf.VRF]:
        vrfs = []
        nb_vrfs = self.query_netbox_graphql(NB_GRAPHQL_VRF_LIST, vrf_prefix_1="CC-CLOUD", vrf_prefix_2="CC-MGMT")
        for nb_vrf in nb_vrfs.vrf_list:
            if nb_vrf.tenant.slug not in self.tenants:
                continue

            rd_suffix = int(nb_vrf.rd.split(":", 1)[1])
            scopes = vrf_to_address_scopes_map.get(nb_vrf.name.lower(), [])
            if not scopes:
                LOG.warning("Could not find any address scopes for VRF %s", nb_vrf.name.lower())
            vrf = conf.VRF(name=nb_vrf.name, number=rd_suffix, address_scopes=scopes)
            vrfs.append(vrf)

        vrfs.sort(key=attrgetter("number"))
        return vrfs

    def make_azs(self, region: str) -> list[conf.AvailabilityZone]:
        azs = []
        site_data = self.query_netbox_graphql(NB_GRAPHQL_REGION_SITE_LIST, region=region)
        for site in site_data.region_list[0].sites:
            suffix = site.slug[len(region):].lower()
            number = ord(suffix) - ord('a') + 1
            azs.append(conf.AvailabilityZone(name=site.slug.lower(), suffix=suffix, number=number))
        azs.sort(key=attrgetter("number"))
        return azs

    @classmethod
    def parse_ccloud_switch_number_resources(cls, device_name: str) -> dict[str, int]:
        """Parse switch number resources specific to CCloud naming scheme

        Should return pod, switchgroup, leaf_no, az_no
        """

        m = cls.switch_name_re.match(device_name)

        if not m:
            raise ConfigSchemeException(f"Could not match '{device_name}' to CCloud hostname scheme "
                                        "(e.g. qa-de-1-sw1234a-bb123)")
        return {
            "pod": int(m.group("pod")),
            "switchgroup_no": int(m.group("switchgroup")),
            # leaf number is calculated by enumerating the leaf chars
            "leaf_no": ord(m.group("leaf")) - ord("a") + 1,
            "az_no": int(m.group('az')),
            "seq_no": int(m.group('seq_no')) if m.group('seq_no') else 0,
            "switchgroup_id": int(m.group('switchgroup_id')),
        }

    def get_region_asn(self, region):
        region_data = self.query_netbox_graphql(NB_GRAPHQL_REGION_SITE_LIST, region=region)
        sites = region_data.region_list[0].sites
        site_asns = {site.custom_fields['ACI ASN'] for site in sites}
        if not site_asns:
            raise ConfigException(f"Region {region} has no ASN")
        if len(site_asns) > 1:
            raise ConfigException(f"Region {region} has multiple ASNs: {site_asns}")
        return site_asns.pop()

    def make_switch(self, switch: Munch, asn_region: int, user: str | None, password: str | None) -> conf.Switch:
        # get primary ip from Loopback10
        lo10_addrs = [ip.display for iface in switch.interfaces for ip in iface.ip_addresses
                      if iface.name == "Loopback10"]
        if len(lo10_addrs) == 0:
            raise ConfigException(f"Device {switch.name} has no IP on Loopback10!")
        if len(lo10_addrs) > 1:
            raise ConfigException(f"Device {switch.name} has multiple IPs on Loopback10! {lo10_addrs}")
        host_ip = lo10_addrs[0].split("/")[0]

        numbered_resources = self.parse_ccloud_switch_number_resources(switch.name)
        bgp_source_ip = "{az_no}.{pod}.{switchgroup_no}.{leaf_no}".format(**numbered_resources)

        return conf.Switch(
            name=switch.name,
            host=host_ip,
            platform=switch.platform.slug,
            bgp_source_ip=bgp_source_ip,
            user=user or "DUMMY_USER",
            password=password or "DUMMY_PASSWORD",
        )

    def make_switchgroup(self, switchgroup_id: int, switches: list[Munch], asn_region: int,
                         switch_user: str | None, switch_password: str | None) -> conf.SwitchGroup:
        members = []
        pod_roles = set()
        azs = set()
        vlan_ranges = None
        for switch in switches:
            # device role (via tag)
            for tag in switch.tags:
                if tag.slug in self.pod_roles:
                    pod_roles.add(self.pod_roles[tag.slug])

            # az
            if not switch.site.slug:
                raise ConfigException(f"Switch {switch.name} has no site assigned to it")
            azs.add(switch.site.slug)

            # custom vlan range
            try:
                new_vlan_ranges = switch.config_context['cc']['net']['evpn']['tenant-vlan-range']
                if new_vlan_ranges and vlan_ranges and new_vlan_ranges != vlan_ranges:
                    raise ConfigException(f"Switchgroup {switchgroup_id} has two competing vlan ranges: "
                                          f"{vlan_ranges} and {new_vlan_ranges}")
                vlan_ranges = new_vlan_ranges
            except KeyError:
                pass

            # finally, create the switch
            conf_switch = self.make_switch(switch, asn_region, switch_user, switch_password)
            members.append(conf_switch)

        if len(members) < 2:
            raise ValueError(f'Switchgroup {switchgroup_id} has only 1 member')
        members.sort(key=lambda x: x.name)

        if len(pod_roles) > 1:
            raise ConfigException(f"Switchgroup {switchgroup_id} has more than one pod role")
        if not pod_roles:
            raise ConfigException(f"Switchgroup {switchgroup_id} is missing a pod role")
        pod_role = pod_roles.pop()

        if len(azs) > 1:
            raise ConfigException(f"Switchgroup {switchgroup_id} has more than one az")
        az = azs.pop()

        # additional data
        numbered_resources = self.parse_ccloud_switch_number_resources(members[0].name)

        # figure out name
        if pod_role == c_const.DEVICE_TYPE_BGW:
            sg_name = f"{pod_role}{switchgroup_id}"
        elif pod_role == c_const.DEVICE_TYPE_TRANSIT:
            # FIXME: can we remove this alltogether?
            raise ConfigException(f"Switchgroup {switchgroup_id} is of type transit, which is no longer supported")
        else:
            pod_seq = numbered_resources['seq_no']
            if pod_seq == 0:
                raise ConfigException(f"Switchgroups {switchgroup_id} has no pod_sequence, e.g. '-bb147/st044/np19'")
            sg_name = f"{pod_role}{pod_seq:03d}"

        # asn / loopback
        if self.use_ebgp:
            asn = "{asn_region}.{az_no}{pod}{switchgroup_no:02d}".format(asn_region=asn_region, **numbered_resources)
        else:
            asn = "{asn_region}.{az_no}".format(asn_region=asn_region, **numbered_resources)
        loopback1 = str(ipaddress.ip_address("{az_no}.{pod}.{switchgroup_no}.0".format(**numbered_resources)))

        sg_args = {
            "name": sg_name,
            "members": members,
            "availability_zone": az,
            "vtep_ip": loopback1,
            "asn": asn,
            "group_id": switchgroup_id,
        }
        if vlan_ranges:
            sg_args['vlan_ranges'] = vlan_ranges

        return conf.SwitchGroup(**sg_args)

    def make_switchgroups(self, switches: list[Munch], asn_region: int,
                          switch_user: str | None, switch_password: str | None) -> list[conf.SwitchGroup]:
        def get_switchgroup_id(switch):
            data = self.parse_ccloud_switch_number_resources(switch.name)
            return data['switchgroup_id']

        switchgroups = []
        switches.sort(key=get_switchgroup_id)

        for switchgroup_id, sg_switches in groupby(switches, key=get_switchgroup_id):
            # handle switchgroup members
            sg_switches = list(sg_switches)
            switchgroup = self.make_switchgroup(switchgroup_id, sg_switches, asn_region, switch_user, switch_password)
            switchgroups.append(switchgroup)
        return switchgroups

    @staticmethod
    def get_vrf_to_address_scope_map(address_scope_vrf_map_config_paths: list[Path]) -> dict[str, list[str]]:
        result = defaultdict(list)
        for path in address_scope_vrf_map_config_paths:
            with path.open('r') as f:
                scope_vrf_map = yaml.safe_load(f)

            for scope_key in ('address_scopes', 'local_address_scopes', 'global_address_scopes'):
                values = scope_vrf_map.get(scope_key)
                if not values:
                    continue

                for i, item in enumerate(values):
                    name = item.get('name')
                    vrf = item.get('vrf')
                    if not name:
                        print(f'{path.as_posix()}, key {scope_key}, item {i}, needs a "name" to be considered '
                              'a valid address-scope mapping')
                        continue

                    if not vrf:
                        print(f'{path.as_posix()}, key {scope_key}, item {i}, needs a "vrf" to be considered '
                              'a valid address-scope mapping')
                        continue

                    result[vrf.lower()].append(name)
        return dict(result)

    @staticmethod
    def wrap_dict(data: dict, path: list[str]) -> dict:
        for key in reversed(path):
            data = {key: data}
        return data

    def generate_credentials(self, switchgroups: list[conf.SwitchGroup], user: str,
                             password: str) -> conf.DriverCredentials:
        creds = {}
        for sg in switchgroups:
            for switch in sg.members:
                creds[switch.name] = conf.Credentials(user=user, password=password)

        return conf.DriverCredentials(switch_credentials=creds)


def merge_configs(new_cfg: conf.DriverConfig, base_cfg: conf.DriverConfig, limit_switches: list[str]) -> None:
    # copy over all missing hostgroups and switchgroups that don't appear in limit_switches
    for sg in base_cfg.switchgroups:
        if any(limit_switch in sw.name
               for sw in sg.members
               for limit_switch in limit_switches):
            continue
        new_cfg.switchgroups.append(sg)

    for hg in base_cfg.hostgroups:
        # a switch limit should always match all switches for a group, so we can take any of them (hopefully)
        if any(limit_switch in sw
               for sw in hg.get_switch_names(base_cfg)
               for limit_switch in limit_switches):
            continue
        new_cfg.hostgroups.append(hg)


def main():
    import argparse
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)-15s %(relativeCreated)7d %(name)-5s %(levelname)-8s %(message)s')

    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--region", required=True)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-u", "--switch-user", help="Default switch user", required=True)
    parser.add_argument("-p", "--switch-password", help="Default switch password")
    parser.add_argument('-V', '--vault-ref',
                        help="Instead of a password, use this vault references, formatted like <path>:<field>")
    parser.add_argument('-c', "--credentials-file",
                        help="Path for a file containing switch credentials. If this is set, all credentials will be "
                             "removed from the generated config and persisted in this file instead.")
    parser.add_argument('--wrap-config-in', default='cc_fabric/driver_config',
                        help='Keys under which the generated config should be nested under. '
                             'Format should be: <key1>/<key2>...')
    parser.add_argument('--wrap-credentials-in', default='cc_fabric/driver_credentials',
                        help='Keys under which the generated credentials should be nested. '
                             'Same as --wrap-config-in')
    parser.add_argument("-a", "--address-scope-vrf-map", type=Path, nargs="+", default=[],
                        help="Path to file containing a mapping of address scope names to VRFs. If this is omitted, "
                             "no mapping will be generated.")
    parser.add_argument("-s", "--shell", action="store_true")
    parser.add_argument("-o", "--output")

    parser.add_argument("-l", "--limit-switches", nargs="*", default=[],
                        help="Only check switches that match these substrings")
    parser.add_argument("-b", "--base-config", type=argparse.FileType("r"),
                        help="Use this driver config as a base and update it "
                             "(only in combination with --limit-switches)")

    args = parser.parse_args()

    if args.verbose:
        LOG.setLevel(logging.DEBUG)
    else:
        LOG.setLevel(logging.INFO)

    if args.switch_password and args.vault_ref:
        parser.error("You may only use one of '--vault-ref' or '--switch-password'")
    if not (args.switch_password or args.vault_ref):
        parser.error("Either'--vault-ref' or '--switch-password' must be set")

    if args.base_config and not args.limit_switches:
        parser.error("--base-config requires --limit-switches")

    if args.vault_ref:
        if not args.vault_ref.startswith("vault+kvv2://"):
            parser.error('Invalid vault reference should start with vault+kvv2://')
        args.switch_password = '{{ resolve "' + args.vault_ref + '" }}'

    for wrap_in in [args.wrap_config_in, args.wrap_credentials_in]:
        if not wrap_in:
            continue
        m = re.match(r'^(?:\w+/)*(?:\w+)$', wrap_in)
        if not m:
            parser.error('Invalid format for --wrap-config-in or --wrap-credentials-in. '
                         f'Should be like <key1>/<key2>..., got {wrap_in}')

    # check if we have a base config (only used after generation, but we want to error out if it's not readable)
    base_config = None
    if args.base_config:
        try:
            base_config_data = yaml.safe_load(args.base_config)
            if args.wrap_config_in:
                # assume the base config is wrapped in the same way as our target config
                for key in args.wrap_config_in.split("/"):
                    if not isinstance(base_config_data, dict) or key not in base_config_data:
                        raise ValueError("Failed to unwrap base config, "
                                         f"expected a dict with key '{key}' at unwrap path")
                    base_config_data = base_config_data[key]

            # patch in potentially missing credentials
            for sg in base_config_data['switchgroups']:
                for sw in sg['members']:
                    sw.setdefault("user", args.switch_user)
                    sw.setdefault("password", args.switch_password)
            base_config = conf.DriverConfig.parse_obj(base_config_data)
        except (ValueError, KeyError) as e:
            print(f"Could not load base config '{args.base_config}': {e}")
            sys.exit(1)

    # generate config
    vrf_to_address_scopes_map = NetboxDataSource.get_vrf_to_address_scope_map(args.address_scope_vrf_map)

    cfggen = NetboxDataSource()
    cfg = cfggen.generate_config(args.region, vrf_to_address_scopes_map, limit_switches=args.limit_switches)

    if base_config:
        merge_configs(cfg, base_config, args.limit_switches)

    # sort it for stable results
    def _hg_sort_key(hg):
        switch_names = ",".join(hg.get_switch_names(cfg))
        hg_meta_name = hg.binding_host_name
        if not hg.metagroup:
            hg_parent = hg.get_parent_metagroup(cfg)
            if hg_parent:
                hg_meta_name = hg_parent.binding_host_name

        return (switch_names, hg_meta_name, not hg.metagroup, hg.binding_host_name)

    # do not sort inplace, as parts of the config might not properly available
    cfg.switchgroups = sorted(cfg.switchgroups, key=lambda sg: sg.name)
    cfg.hostgroups = sorted(cfg.hostgroups, key=_hg_sort_key)

    cfg_data = cfg.dict(exclude_unset=True, exclude_defaults=True, exclude_none=True)

    # remove credentials
    if args.credentials_file:
        # swipe credentials from default config
        for sg in cfg_data['switchgroups']:
            for member in sg['members']:
                del member['user']
                del member['password']

        creds = cfggen.generate_credentials(cfg.switchgroups, args.switch_user, args.switch_password)
        cred_data = creds.dict()
        if args.wrap_credentials_in:
            cred_data = cfggen.wrap_dict(cred_data, args.wrap_credentials_in.split('/'))
        LOG.debug("Writing %s ...", args.credentials_file)
        with open(args.credentials_file, "w") as f:
            yaml.safe_dump(cred_data, f)

    if args.output:
        if args.wrap_config_in:
            cfg_data = cfggen.wrap_dict(cfg_data, args.wrap_config_in.split('/'))

        if args.output == '-':
            print(yaml.safe_dump(cfg_data))
        else:
            LOG.debug("Writing %s ...", args.output)
            with open(args.output, "w") as f:
                yaml.safe_dump(cfg_data, f)

    if args.shell:
        import IPython
        IPython.embed()


if __name__ == '__main__':
    main()
