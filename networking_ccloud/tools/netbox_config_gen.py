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
from itertools import chain, groupby
import logging
from operator import attrgetter, itemgetter
from pathlib import Path
import re
import urllib3
from typing import Any, Dict, Generator, Iterable, List, Optional, Set, Tuple, Union

import pynetbox
from pynetbox.core.response import Record as NbRecord
import requests
import yaml

from networking_ccloud.common.config import config_driver as conf
from networking_ccloud.common import constants as c_const

LOG = logging.getLogger(__name__)

SWITCHGROUP_ROLE_VPOD = 'bb'
SWITCHGROUP_ROLE_STPOD = 'st'
SWITCHGROUP_ROLE_APOD = 'ap'
SWITCHGROUP_ROLE_NETPOD = 'np'

RESPONSIBLE_LAG_RANGES = (101, 199)
DEFAULT_VLAN_RANGES = ["2000:3750"]
NETWORK_AGENTS_PER_APOD = 15

VAULT_REF_REPLACEMENT = 'VAULTER-WHITE-REPLACE-ME'


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
    lag_id_re = re.compile(r"^\S+?(?P<lag_id>\d+)$")
    apod_node_name_re = re.compile(r'^node\d+-ap(?P<apod_seq>\d+)$')
    filer_parent_name_re = re.compile(r'^stnpca(?P<cluster_seq>\d+)-st(?P<stpod_seq>\d+)$')
    loadbalancer_vm_name_re = re.compile(
        r'^(?P<region>\w{2}-\w{2}-\d)-(?P<cluster_name>lb\d{3})(?P<ha_role>[a|b])-(?P<seq>\d{2})$')

    leaf_role = "evpn-leaf"
    spine_role = "evpn-spine"
    connection_roles = {"server", "neutron-router", "filer", 'loadbalancer'}
    manila_tag = "manila"
    infra_network_vrf = 'CC-MGMT'
    tenants = {"converged-cloud"}
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

    # metagroup handlers

    def vpod_metagroup_handler(self, cluster: NbRecord, member: NbRecord) -> Optional[conf.Hostgroup]:
        # FIXME: CCloud specific name generation
        cname: str = cluster.name  # type: ignore
        ctype = cluster.type.slug  # type: ignore
        if not cname.startswith("production"):
            print(f"Warning: Cluster {cname} of type {ctype} does not start "
                  "with 'production' - ignoring")
            return None
        binding_host = "nova-compute-{}".format(cname[len("production"):])
        return conf.Hostgroup(binding_hosts=[binding_host], metagroup=True, members=[member.name])

    def neutron_router_metagroup_handler(self, cluster: NbRecord, member: NbRecord) -> Optional[conf.Hostgroup]:
        cname: str = cluster.name  # type: ignore
        cprefix = f'{self.region}-'
        if not cname.startswith(cprefix):
            raise ValueError(f'Cluster {cname} must start with {cprefix}')
        cname = cname[len(cprefix):]
        return conf.Hostgroup(binding_hosts=[cname], metagroup=True, members=[member.name])

    def f5_loadbalancer_metagroup_handler(self, cluster: NbRecord, member: NbRecord) -> Optional[conf.Hostgroup]:
        binding_hosts = []
        for vm in self.netbox.virtualization.virtual_machines.filter(cluster_id=cluster.id):
            m = self.loadbalancer_vm_name_re.match(vm.name)
            if m:
                # VMs in netbox will be named like
                # {region}-lb414a-01, {region}-lb414b-01 -> binding host should be lb414-01
                cname, cseq = m.group('cluster_name'), m.group('seq')
                binding_hosts.append(f'{cname}-{int(cseq):02d}')

        if not binding_hosts:
            print(f'Warning - Loadbalancer cluster {cluster.name} has no VM that complies with binding host naming')
            return None

        # Reject binding hosts with just one VM
        binding_host_counter = Counter(binding_hosts)
        binding_hosts = []
        for binding_host, cnt in binding_host_counter.items():
            if cnt < 2:
                print(f'Warning - Loadbalancer binding host {binding_host} has only one VM in cluster {cluster.name}'
                      ' - omitting binding host')
            elif cnt > 2:
                print(f'Warning - Loadbalancer binding host {binding_host} has more than 2 VMs in cluster '
                      f'{cluster.name}, omitting binding host')
            else:
                binding_hosts.append(binding_host)
        return conf.Hostgroup(binding_hosts=sorted(binding_hosts), metagroup=True, members=[member.name])

    def apod_metagroup_handler(self, cluster: NbRecord, member: NbRecord) -> Optional[conf.Hostgroup]:
        m = self.apod_node_name_re.match(member.name)
        if not m:
            raise ValueError(f'{member.name} is not complying with expected node naming for apod clusters')
        apod_sequence = int(m.group('apod_seq'))
        binding_host_prefix = f'neutron-network-agent-ap{apod_sequence:03d}-'
        # right now 15 network agents are statically created per apod
        binding_hosts = [f'{binding_host_prefix}{x}' for x in range(0, NETWORK_AGENTS_PER_APOD)]
        return conf.Hostgroup(binding_hosts=binding_hosts, metagroup=True, members=[member.name])

    def filer_metagroup_handler(self, parent: NbRecord, member: NbRecord) -> Optional[conf.Hostgroup]:
        m = self.filer_parent_name_re.match(parent.name)
        if not m:
            raise ValueError(f'{parent.name} is not complying with expected node naming for stpod parents')
        if parent.parent_device:
            raise ValueError(f'{parent.name} is a filer chassis and should not have a parent device')
        binding_host = f'manila-share-netapp-{parent.name}'
        return conf.Hostgroup(binding_hosts=[binding_host], metagroup=True, members=[member.name])

    def noop_metagroup_handler(self, cluster: NbRecord, member: NbRecord) -> Optional[conf.Hostgroup]:
        # In case we still care about the cluster type, but just do not need a metagroup from it
        return None

    metagroup_handlers = {
        'cc-vsphere-prod': vpod_metagroup_handler,
        'neutron-router-pair': neutron_router_metagroup_handler,
        'cc-k8s-controlplane': apod_metagroup_handler,
        'filer': filer_metagroup_handler,
        'cc-vsphere-apod-mgmt': noop_metagroup_handler,
        'cc-vsphere-apod-pool': noop_metagroup_handler,
        'cc-k8s-controlplane-swift': noop_metagroup_handler,
        'cc-f5-vcmp': f5_loadbalancer_metagroup_handler,
    }

    def __init__(self, region, args, verbose=False, verify_ssl=False):
        self.region = region
        self.args = args
        self.verbose = verbose

        self.netbox = pynetbox.api(self.netbox_url, threading=True)
        if not verify_ssl:
            urllib3.disable_warnings()
            self.netbox.http_session = requests.Session()
            self.netbox.http_session.verify = False

    @classmethod
    def _ignore_filter(cls, items: Iterable[NbRecord]) -> Generator[NbRecord, None, None]:
        for item in items:
            if any(x.slug in cls.ignore_tags for x in getattr(item, 'tags', list())):
                print(f'Item {item.url} has ignore tag set')
            else:
                yield item

    @classmethod
    def switch_filter(cls, switches: Iterable[NbRecord]) -> Generator[NbRecord, None, None]:
        for switch in cls._ignore_filter(switches):
            tags = [x.slug for x in getattr(switch, 'tags', list())]
            # ensure the switch has at least one tag that we care about
            if not any((x in cls.pod_roles.keys() for x in tags)):
                print(f"Device {switch.name} has none of the supported functional tags")
                continue
            if getattr(switch.platform, 'slug', None) not in c_const.PLATFORMS:
                print(f"Warning: Device {switch.name} is of platform {getattr(switch.platform, 'slug', None)}, "
                      "which is not supported by the driver/config generator")
                continue
            yield switch

    @classmethod
    def _ensure_single_item(cls, item_set: Iterable[Any], entity: str, identifier: str, attribute: str) -> Any:
        if not isinstance(item_set, set):
            item_set = set(item_set)
        if len(item_set) != 1:
            raise ConfigSchemeException(f'{entity} identified by {identifier}: '
                                        f'Unexpected values for {attribute}, expected 1 but got {len(item_set)}')
        return item_set.pop()

    def get_azs(self) -> List[conf.AvailabilityZone]:
        azs = list()
        for site in self.netbox.dcim.sites.filter(region=self.region):
            suffix = site.slug[len(self.region):].lower()
            number = ord(suffix) - ord('a') + 1
            azs.append(conf.AvailabilityZone(name=site.slug, suffix=suffix, number=number))
        return sorted(azs, key=attrgetter('number'))

    def get_address_scopes(self, address_scope_vrf_maps_path: List[Path]) -> Dict[str, List[str]]:
        result = defaultdict(list)
        for p in address_scope_vrf_maps_path:
            with p.open('r') as f:
                asvm = yaml.safe_load(f)
                for k in ('address_scopes', 'local_address_scopes', 'global_address_scopes'):
                    values = asvm.get(k)
                    if not values:
                        continue
                    for i, item in enumerate(values):
                        name = item.get('name')
                        vrf = item.get('vrf')
                        if not name:
                            print(f'{p.as_posix()}, key {k}, item {i}, needs a "name" to be considered '
                                  'a valid address-scope mapping')
                            continue
                        if not vrf:
                            print(f'{p.as_posix()}, key {k}, item {i}, needs a "vrf" to be considered '
                                  'a valid address-scope mapping')
                            continue
                        result[vrf.lower()].append(name)
        return result

    def get_cloud_vrfs(self, address_scope_vrf_maps_path) -> List[conf.VRF]:
        vrfs = list()
        search_strings = ['CC-CLOUD', 'CC-MGMT']
        address_scopes = self.get_address_scopes(address_scope_vrf_maps_path)
        nb_return = chain(*(self.netbox.ipam.vrfs.filter(q=x, tenant=self.tenants) for x in search_strings))
        for vrf in nb_return:
            rd_suffix = int(vrf.rd[vrf.rd.find(':') + 1:])
            scopes = address_scopes.get(vrf.name.lower(), [])
            if address_scope_vrf_maps_path and not scopes:
                print(f'I could not find any addres-scopes for VRF {vrf.name}')
            vrfs.append(conf.VRF(name=vrf.name, number=rd_suffix, address_scopes=scopes))  # type: ignore
        return sorted(vrfs, key=attrgetter('number'))

    @classmethod
    def parse_ccloud_switch_number_resources(cls, device_name: str) -> Dict[str, int]:
        """Parse switch number resources specific to CCloud naming scheme

        Should return pod, switchgroup, leaf_no, az_no
        """

        m = cls.switch_name_re.match(device_name)

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

    @classmethod
    def sort_switchports(cls, switchports: List[conf.SwitchPort]) -> List[conf.SwitchPort]:

        def keyfunc(sp: conf.SwitchPort) -> Tuple[Union[int, str]]:
            if sp.name:
                tokens = re.split(r"(\d+)", sp.name)
                return tuple(int(x) if x.isdecimal() else x for x in tokens)
            else:
                return tuple(sp.switch)

        return sorted(switchports, key=keyfunc)

    @classmethod
    def handle_interface_or_portchannel(cls, iface: NbRecord, candidate_interfaces: List[conf.SwitchPort],
                                        switchport_kwargs: Dict[str, Any] = {}):

        device_name = iface.device.name  # type: ignore
        if iface.lag is not None:
            # make sure the Port-Channel is not ignored
            if not next(cls._ignore_filter([iface.lag]), False):
                return candidate_interfaces
            # We fill this list only if this filter comes back False, so this is assumed to be unique
            lags = filter(lambda x: x.switch == device_name and
                          x.name == iface.lag.name and x.lacp, candidate_interfaces)  # type: ignore
            lag: Optional[conf.SwitchPort] = next(lags, None)
            if lag:
                lag.members.append(iface.name)
            else:
                candidate_interfaces.append(conf.SwitchPort(switch=device_name, lacp=True,
                                                            name=iface.lag.name, members=[iface.name],
                                                            **switchport_kwargs))
        else:
            # not a lag
            candidate_interfaces.append(conf.SwitchPort(switch=device_name, name=iface.name, **switchport_kwargs))
        return candidate_interfaces

    def get_svi_ips_per_vlan(self, device: NbRecord) -> Dict[NbRecord, List[NbRecord]]:
        all_ips = self.netbox.ipam.ip_addresses.filter(device_id=device.id, role='anycast')
        vlan_ips = defaultdict(list)
        for ip in all_ips:
            if ip.assigned_object.untagged_vlan:
                vlan_ips[ip.assigned_object.untagged_vlan].append(ip)
        return vlan_ips

    def derive_vlan_vni(self, vlan: NbRecord) -> int:
        # https://sapcc.github.io/networking-ccloud/configuration/config-input.html#vlan-to-vni
        # check if bb-local switchgroup significant VLAN
        if vlan.group.slug.startswith('cc-vpod'):  # type: ignore
            # we would actually like to use the vlan group's scope type,
            # yet netbox only allows a per rack/site/region scope type
            # but out vpods span over multiple racks, so we have to use
            # a site scope type and need to fallback on regex parsing here

            # expects something like cc-vpod271
            m = re.match(r'.*?(\d+)$', vlan.group.slug)  # type: ignore
            if not m:
                raise ConfigException(f'vlan group {vlan.group.slug} must end with digits '  # type: ignore
                                      ' identifying the bb/np/stp')
            pod_sequence = int(m.group(1))
            return int(f'10{pod_sequence:03d}{vlan.vid:03d}')
        raise NotImplementedError(f'Cannot derive VNID for vlan {dict(vlan)}')

    def get_infra_network_l3_data(self, iface: NbRecord, vlan: NbRecord,
                                  svis: Dict[NbRecord, List[NbRecord]]) -> Tuple[List[str], Set[str]]:
        parent_prefixes = set()
        networks = list()
        for gateway in svis[vlan]:
            prefix = ipaddress.ip_network(gateway.address, strict=False)
            # make sure that the svi interface's address actually resides in the correct prefix
            nb_prefix = self.netbox.ipam.prefixes.get(vlan_id=vlan.id, prefix=prefix.with_prefixlen)
            if not nb_prefix:
                raise ConfigException(f'Vlan {vlan.id} bound on interface {iface.id} is l3 enabled, but SVI '
                                      f'interface\'s address {gateway.address} address does not reside in the '
                                      'vlan\'s assigned prefix')
            if not gateway.vrf or gateway.vrf.name != self.infra_network_vrf:
                raise ConfigException(f'Gateway address {gateway} with ID {gateway.id} does not reside in VRF '
                                      f'{self.infra_network_vrf} but must for InfraNetwork '
                                      f'(current VRF {gateway.vrf})')
            networks.append(gateway.address)
            nb_parent_prefix = self.netbox.ipam.prefixes.get(contains=prefix.with_prefixlen,
                                                             vrf_id=nb_prefix.vrf.id,
                                                             tenant_id=nb_prefix.tenant.id,
                                                             site_id=nb_prefix.site.id,
                                                             mask_length__lte=prefix.prefixlen - 1)
            if not nb_parent_prefix:
                raise ConfigException(f'Could not find supernet for {gateway.address}')
            parent_prefixes.add(ipaddress.ip_network(nb_parent_prefix.prefix))
        return networks, parent_prefixes

    def make_infra_networks_and_extra_vlans(self, iface: NbRecord, svis: Dict[NbRecord, List[NbRecord]]
                                            ) -> Tuple[Set[conf.InfraNetwork], Set[int]]:
        # lag superseeds physcal interface
        infra_nets = set()
        extra_vlans = set()
        if iface.lag:
            iface = iface.lag

        # FIXME: support untagged VLANs
        # FIXME: support DHCP relay
        for vlan in getattr(iface, 'tagged_vlans', list()):
            # some infra vlans we will not manage, just put in the allowed VLAN list
            tags = set(x.slug for x in vlan.tags)
            if vlan.group and hasattr(vlan.group, 'tags'):
                tags.update(x.slug for x in vlan.group.tags)
            if self.extra_vlan_tag in tags:
                extra_vlans.add(vlan.vid)
                continue

            # by convention we ignore certain VLAN groups member VLANs, once we upgrade to netbox 3.x we shall remove
            # this as VLAN groups will then support tags
            if vlan.group and (
                    (vlan.group.slug.startswith(self.region) and vlan.group.slug.endswith('cp'))
                    or vlan.group.slug == f'{self.region}-regional'
                    or vlan.group.slug == 'global-cc-core-transit'):
                extra_vlans.add(vlan.vid)
                continue

            mandatory_attrs = ('vid', 'tenant')
            for attr in mandatory_attrs:
                if not getattr(vlan, attr, None):
                    raise ConfigException(f'VLAN {vlan.id} has no attribute {attr}')
            if vlan.tenant.slug not in self.tenants:
                continue
            if not getattr(vlan, 'group', None):
                raise ConfigException(f'vlan {vlan.id} has no VLAN group')
            vni = self.derive_vlan_vni(vlan)

            networks, parent_prefixes = self.get_infra_network_l3_data(iface, vlan, svis)

            infra_net_name = f'{vlan.group.name.lower().replace(" ", "-")}-{vlan.name.lower().replace(" ", "-")}'
            if len(parent_prefixes) > 1:
                raise ConfigException(f'For {infra_net_name} the prefixes are sourced from multiple parent '
                                      f'networks {parent_prefixes}')

            if len(parent_prefixes) == 0:
                raise ConfigException(f"Missing parent prefix for infra net {infra_net_name} "
                                      f"(svi map for vlan {vlan} was {svis[vlan]})")

            infra_net = conf.InfraNetwork(name=infra_net_name, vlan=vlan.vid, vrf=self.infra_network_vrf,
                                          networks=networks, vni=vni, aggregates=[str(parent_prefixes.pop())])

            infra_nets.add(infra_net)
        return infra_nets, extra_vlans

    @classmethod
    def get_switchgroup_attributes(cls, devices: List[NbRecord]) -> Dict[str, str]:

        attributes = dict()
        pod_roles = set()
        azs = set()
        vlan_ranges = set()

        for device in devices:

            # roles
            if device.tags:
                pod_roles = set(filter(lambda x: x, (cls.pod_roles.get(x.slug, None) for x in device.tags)))

            # azs
            if not device.site:
                raise ConfigException(f'{device.name} must have a site')
            azs.add(device.site.slug)

            # segment ranges
            if device.config_context:
                vlan_range = device.config_context.get('cc', {}) \
                                                  .get('net', {}) \
                                                  .get('evpn', {}) \
                                                  .get('tenant-vlan-range')
                if vlan_range:
                    if not isinstance(vlan_range, list):
                        raise ConfigException(f'cc/net/evpn/tenant-vlan-range in config context of {device.name}'
                                              ' must be a list.')
                    for r in vlan_range:
                        try:
                            conf.validate_vlan_ranges(r)
                        except ValueError as e:
                            raise ConfigException(f'{device.name} has invalid tenant-vlan-range: {e}')
                    vlan_range = tuple(sorted(vlan_range))
                    vlan_ranges.add(vlan_range)

        # silently reject switches without a role, could be BL or anything we do not care about
        if not pod_roles:
            return dict()

        attributes['pod_role'] = cls._ensure_single_item(pod_roles, 'Switchgroup',
                                                         ', '.join(x.name for x in devices), 'pod_roles')
        attributes['az'] = cls._ensure_single_item(azs, 'Switchgroup',
                                                   ', '.join(x.name for x in devices), 'azs')
        if vlan_ranges:
            attributes['vlan_ranges'] = list(cls._ensure_single_item(vlan_ranges, 'Switchgroup',
                                                                     ', ' .join(x.name for x in devices),
                                                                     'vlan_ranges'))
        return attributes

    def get_switchgroup_name(self, role: str, switchgroup_id: int, pod_sequence: int):
        if role in {c_const.DEVICE_TYPE_BGW, c_const.DEVICE_TYPE_TRANSIT}:
            return f"{role}{switchgroup_id}"
        if pod_sequence == 0:
            raise ConfigException("Switchgroups {switchgroup_id} has no pod_sequence, e.g. '-bb147/st044/np19'")
        return f"{role}{pod_sequence:03d}"

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

    def make_switch(self, asn_region: int, switch: NbRecord, user: str, password: str) -> conf.Switch:
        # get primary ip from Loopback10
        lo10_addr = list(self.netbox.ipam.ip_addresses.filter(interface="Loopback10", device_id=switch.id))
        if len(lo10_addr) == 0:
            raise ConfigException(f"Device {switch.name} has no IP on Loopback10!")
        if len(lo10_addr) > 1:
            raise ConfigException(f"Device {switch.name} has multiple IPs on Loopback10! {lo10_addr}")
        host_ip = lo10_addr[0].address.split("/")[0]

        numbered_resources = self.parse_ccloud_switch_number_resources(switch.name)
        l3_data = self.get_l3_data(asn_region, **numbered_resources)

        return conf.Switch(
            name=switch.name,
            host=host_ip,
            platform=getattr(switch.platform, 'slug'),
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
                members.append(conf_switch)
            if len(members) < 2:
                raise ValueError(f'Switchgroup {switchgroup_id} has only 1 member')
            # FIXME: Warn when a switchgroup is larger 2
            # we derive loopback1/asn from switch_number_resources which we already grouped on
            # so a switchgroup is guranteed to have the same values
            members.sort(key=lambda x: x.name)
            numbered_resources = self.parse_ccloud_switch_number_resources(members[0].name)
            l3_data = self.get_l3_data(asn_region, **numbered_resources)
            sg_name = self.get_switchgroup_name(sg_attributes['pod_role'], numbered_resources['switchgroup_id'],
                                                numbered_resources['seq_no'])
            sg_args = dict(name=sg_name, members=members, availability_zone=sg_attributes['az'],
                           vtep_ip=l3_data['loopback1'], asn=l3_data['asn'], group_id=switchgroup_id)
            if 'vlan_ranges' in sg_attributes:
                sg_args['vlan_ranges'] = sg_attributes['vlan_ranges']
            switchgroup = conf.SwitchGroup(**sg_args)
            switchgroups.append(switchgroup)
        return switchgroups

    def get_connected_devices(self, switches: List[NbRecord]) -> Tuple[Set[NbRecord], List[conf.Hostgroup]]:
        device_ports_map: Dict[NbRecord, List[conf.SwitchPort]] = defaultdict(list)
        device_infra_nets_map: Dict[NbRecord, Tuple[Set[conf.InfraNetwork], Set[int]]] = dict()

        for switch in switches:
            svi_vlan_ip_map = self.get_svi_ips_per_vlan(switch)
            ifaces = self._ignore_filter(self.netbox.dcim.interfaces.filter(device_id=switch.id))
            for iface in ifaces:
                # For now, we decided there are no non-lag connected devices.
                # Those that we find unbundled are probably not modelled correctly, so we exclude them.
                if not iface.lag:
                    continue
                m = self.lag_id_re.match(iface.lag.name)
                if not m:
                    print(f'Cannot parse LAG id on interface {switch.name}/{iface.name}, '
                          f'bundled in {iface.lag.name}')
                lag_id = int(m.group('lag_id'))

                if not RESPONSIBLE_LAG_RANGES[0] <= lag_id <= RESPONSIBLE_LAG_RANGES[1]:
                    if self.verbose:
                        print(f'LAG id {lag_id} on {switch.name}/{iface.lag.name} is oustide of driver '
                              f'responsible bounds [{RESPONSIBLE_LAG_RANGES[0]}, {RESPONSIBLE_LAG_RANGES[1]}]')
                    continue

                # FIXME: ignore management, peerlink (maybe), unconnected ports
                if iface.connected_endpoint is None:
                    continue

                far_device = iface.connected_endpoint.device
                if far_device.device_role.slug not in self.connection_roles:
                    continue
                if (far_device.device_role.slug == 'filer'
                   and far_device.parent_device
                   and self.manila_tag not in {x.slug for x in far_device.parent_device.tags}):
                    continue
                if getattr(far_device.tenant, 'slug', None) not in self.tenants:
                    continue

                if self.verbose:
                    print(f"Device {switch.name} port {iface.name} is connected to "
                          f"device {far_device.name} port {iface.connected_endpoint.name} "
                          f"role {far_device.device_role.name}")

                ports_to_device = device_ports_map.get(far_device, [])
                # ensure InfraNetworks are symmetric
                infra_nets_and_extra_vlans = self.make_infra_networks_and_extra_vlans(iface, svi_vlan_ip_map)
                if far_device in device_infra_nets_map:
                    if device_infra_nets_map[far_device] != infra_nets_and_extra_vlans:
                        raise ConfigException(f'Host {far_device.name} has asymmetric infra networks on both switches')
                else:
                    device_infra_nets_map[far_device] = infra_nets_and_extra_vlans
                device_ports_map[far_device] = self.handle_interface_or_portchannel(iface, ports_to_device)

        hgs = [conf.Hostgroup(binding_hosts=[h.name], direct_binding=True, members=self.sort_switchports(m),
                              infra_networks=sorted(device_infra_nets_map[h][0], key=lambda x: x.vlan),
                              extra_vlans=sorted(device_infra_nets_map[h][1]) if device_infra_nets_map[h][1] else None)
               for h, m in device_ports_map.items()]
        return set(device_ports_map.keys()), hgs

    def get_interconnect_hostgroups(self, nb_switches: List[NbRecord]) -> List[conf.Hostgroup]:
        interconnects: Dict[int, conf.Hostgroup] = dict()
        for nb_switch in nb_switches:
            roles = {self.pod_roles.get(t.slug) for t in getattr(nb_switch, 'tags', [])}
            if c_const.DEVICE_TYPE_BGW in roles:
                switchgroup_id = self.parse_ccloud_switch_number_resources(nb_switch.name)['switchgroup_id']
                swp = conf.SwitchPort(switch=nb_switch.name, name=None)
                hg = interconnects.get(switchgroup_id)
                if not hg:
                    hg = conf.Hostgroup(binding_hosts=[f'{c_const.DEVICE_TYPE_BGW}{switchgroup_id}'],
                                        handle_availability_zones=[getattr(nb_switch.site, 'slug', None)],
                                        role=c_const.DEVICE_TYPE_BGW, members=[swp])
                    interconnects[switchgroup_id] = hg
                else:
                    hg.members.append(swp)  # type: ignore
            if c_const.DEVICE_TYPE_TRANSIT in roles:

                # Fiddle out AZ that this transit handles from config context
                handled_azs = [getattr(nb_switch.site, 'slug', None)]
                additional_azs = getattr(nb_switch, 'config_context', dict())
                for item in ('cc', 'net', 'evpn', 'transit', 'handles_azs'):
                    additional_azs = additional_azs.get(item, dict())
                if additional_azs:
                    handled_azs.extend(additional_azs)

                switchgroup_id = self.parse_ccloud_switch_number_resources(nb_switch.name)['switchgroup_id']

                # Find all interfaces connected to a device of type aci-leaf and add them as members to the hg
                ifaces = self._ignore_filter(self.netbox.dcim.interfaces.filter(device_id=nb_switch.id))
                aci_facing_ifaces = list()
                for iface in ifaces:
                    connected_device_role = iface
                    for attr in ('connected_endpoint', 'device', 'device_role', 'slug'):
                        connected_device_role = getattr(connected_device_role, attr, None)
                    if not connected_device_role:
                        continue
                    if connected_device_role == "aci-leaf":
                        # This can be VPCs on ACI side, so it makes no sense to group on remote devices.
                        # We just group them on the same port-channel name
                        # Transit interfaces are for now marked as unmanaged, as we don't have the full vlan list
                        aci_facing_ifaces = self.handle_interface_or_portchannel(iface, aci_facing_ifaces,
                                                                                 switchport_kwargs={'unmanaged': True})

                if not aci_facing_ifaces:
                    raise ConfigException(f'{nb_switch.name} is labelled as transit but has no ACI facing interfaces')

                if len(aci_facing_ifaces) > 1:
                    raise ConfigException(f'On {nb_switch} found {", ".join(x.name for x in aci_facing_ifaces)} '
                                          'facing to the same device. This must be a single Port-channel or it '
                                          'might form a loop')

                hg = interconnects.get(switchgroup_id)
                if not hg:
                    hg = conf.Hostgroup(binding_hosts=[f'{c_const.DEVICE_TYPE_TRANSIT}{switchgroup_id}'],
                                        handle_availability_zones=handled_azs,
                                        role=c_const.DEVICE_TYPE_TRANSIT, members=aci_facing_ifaces)
                    interconnects[switchgroup_id] = hg
                else:
                    hg.members.extend(aci_facing_ifaces)

        interconnects_with_sorted_members = list()
        for interconnect in interconnects.values():
            interconnect.members = self.sort_switchports(interconnect.members)  # type: ignore
            interconnects_with_sorted_members.append(interconnect)

        return interconnects_with_sorted_members

    @classmethod
    def cluster_is_valid(cls, cluster: NbRecord) -> bool:
        if not cluster.name:
            print(f'Warning: Cluster {cluster.id} has no name - ignoring')
            return False
        if not cluster.type:
            print(f'Warning: Cluster {cluster.name} has no type - ignoring')
            return False
        if cluster.type.slug not in cls.metagroup_handlers:
            print(f'Warning: Cluster {cluster.name} has unsupported type {cluster.type.slug} - ignoring')
            return False
        return True

    @classmethod
    def parent_is_valid(cls, parent: NbRecord) -> bool:
        if not parent.name:
            print(f'Warning: Parent {parent.id} has no name - ignoring')
            return False
        if not parent.device_role:
            print(f'Warning: Parent {parent.name} has no type - ignoring')
            return False
        if parent.device_role.slug not in cls.metagroup_handlers:
            print(f'Warning: Parent {parent.name} has unsupported type {parent.device_role.slug} - ignoring')
            return False
        return True

    def get_metagroups(self, connected_devices: Set[NbRecord]) -> List[conf.Hostgroup]:
        metagroups: Dict[str, conf.Hostgroup] = dict()
        for device in connected_devices:
            if not device.cluster and not device.parent_device:
                continue
            if device.cluster:
                cluster = device.cluster
                handler = cluster.type.slug
                if not self.cluster_is_valid(cluster):
                    continue
            # clusters take precedence over parents (let's see how long that will hold)
            elif device.parent_device:
                cluster = device.parent_device
                handler = cluster.device_role.slug
                if not self.parent_is_valid(cluster):
                    continue
            else:
                # Everything that has neither a cluster nor a parent we ignore
                continue
            # there must be a handler, otherwise the cluster/parent would not be valid
            metagroup = self.metagroup_handlers[handler](self, cluster, device)
            if not metagroup:
                # something failed here, so we ignore
                continue
            # unfortunately the assumption that a netbox cluster corresponds to a metagroup does not hold with
            # with apods anymore, hence, we call the metagroup handler and then use the binding_host to check
            # if that metagroup exists
            existing = metagroups.get(metagroup.binding_host_name)
            if not existing:
                metagroups[metagroup.binding_host_name] = metagroup
            else:
                existing.members.append(device.name)

        for name, metagroup in metagroups.items():
            metagroup.members.sort()  # type: ignore
        return list(metagroups.values())

    @classmethod
    def purge_infranetworks_on_metagroup(cls, metagroup: conf.Hostgroup, member_hgs: List[conf.Hostgroup]):
        if not metagroup.metagroup:
            raise ValueError('Argument metagroup must be a metagroup')
        metagroup_members = set(metagroup.members)
        members_hgs_binding_hosts = set(x.binding_hosts[0] for x in member_hgs)
        if metagroup_members != members_hgs_binding_hosts:
            raise ValueError("'member_hgs.binding_host[0]' and metagroup.members are not matching")

        minimum_common_infra_nets = set(member_hgs[0].infra_networks)
        minimum_common_extra_vlans = set(member_hgs[0].extra_vlans or [])
        for member in member_hgs:
            minimum_common_infra_nets.intersection_update(member.infra_networks)
            minimum_common_extra_vlans.intersection_update(member.extra_vlans or [])

        # purge them from the member_hgs
        for member in member_hgs:
            remaining_infra_nets = list()
            remaining_extra_vlans = list()
            for infra_net in member.infra_networks:
                if infra_net not in minimum_common_infra_nets:
                    remaining_infra_nets.append(infra_net)
            for extra_vlan in member.extra_vlans or []:
                if extra_vlan not in minimum_common_extra_vlans:
                    remaining_extra_vlans.append(extra_vlan)
            member.infra_networks = remaining_infra_nets
            member.extra_vlans = remaining_extra_vlans or None
        metagroup.infra_networks = sorted(minimum_common_infra_nets, key=attrgetter('vlan'))
        if minimum_common_extra_vlans:
            metagroup.extra_vlans = sorted(minimum_common_extra_vlans)

    def generate_config(self):

        switch_user = self.args.switch_user
        switch_password = self.args.switch_password
        address_scope_vrf_maps_path = self.args.address_scope_vrf_map

        nb_switches = list(self.switch_filter(self.netbox.dcim.devices.filter(region=self.region, role=self.leaf_role,
                                                                              status='active')))
        interconnect_hostgroups = sorted(self.get_interconnect_hostgroups(nb_switches),
                                         key=lambda x: x.binding_hosts[0])
        asn_region = self.get_asn_region(self.region)
        switchgroups = sorted(self.get_switchgroups(asn_region, nb_switches, switch_user, switch_password),
                              key=lambda x: x.name)
        connected_devices, direct_hgs = self.get_connected_devices(nb_switches)
        metagroups = sorted(self.get_metagroups(connected_devices), key=lambda x: x.binding_hosts[0])

        binding_host_hg_map = {hg.binding_hosts[0]: hg for hg in direct_hgs}

        global_config = conf.GlobalConfig(asn_region=asn_region, default_vlan_ranges=DEFAULT_VLAN_RANGES,
                                          vrfs=self.get_cloud_vrfs(address_scope_vrf_maps_path),
                                          availability_zones=self.get_azs())

        # FIXME: meta hostgroups based on device-role
        # FIXME: check that no hostgroup has switches from two different switchgroups
        binding_hosts_in_metagroup = set()
        hostgroups = list()
        for metagroup in metagroups:
            direct_binding_hosts = [binding_host_hg_map[member] for member in metagroup.members  # type: ignore
                                    if binding_host_hg_map.get(member)]  # type: ignore
            binding_hosts_in_metagroup.update(x.binding_hosts[0] for x in direct_binding_hosts)
            self.purge_infranetworks_on_metagroup(metagroup, direct_binding_hosts)
            hostgroups.extend(direct_binding_hosts)
            hostgroups.append(metagroup)

        missing_hosts = sorted(binding_host_hg_map.keys() - binding_hosts_in_metagroup)
        for host in missing_hosts:
            hostgroups.append(binding_host_hg_map[host])

        hostgroups.extend(interconnect_hostgroups)

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
    parser.add_argument("-p", "--switch-password", help="Default switch password")
    parser.add_argument('-V', '--vault-ref',
                        help="Instead of a password, use this vault references, formatted like <path>:<field>")

    parser.add_argument('-w', '--wrap-in', help='Keys under which the generated config should be nested under. '
                                                'Format should be: <key1>/<key2>...')
    parser.add_argument("-a", "--address-scope-vrf-map", type=Path, nargs="+",
                        help="Path to file containing a mapping of address scope names to VRFs. If this is omitted, "
                             "no mapping will be generated.")
    parser.add_argument("-s", "--shell", action="store_true")
    parser.add_argument("-o", "--output")

    args = parser.parse_args()

    if args.switch_password and args.vault_ref:
        parser.error("You may only use one of '--vault-ref' or '--switch-passsword'")
    if not (args.switch_password or args.vault_ref):
        parser.error("Either'--vault-ref' or '--switch-passsword' must be set")

    if args.vault_ref:
        args.switch_password = VAULT_REF_REPLACEMENT
        m = re.match(r'^(?P<path>\S+)\W*:\W*(?P<field>\S+)', args.vault_ref)
        if m:
            vault_path, vault_field = m.group('path'), m.group('field')
        else:
            parser.error(f'Invalid vault reference should be <path>:<field>, got {args.vault_ref}')

    if args.wrap_in:
        m = re.match(r'^(?:\w+/)*(?:\w+)$', args.wrap_in)
        if not m:
            parser.error(f'Invalid format for --wrap-in. Should be like <key1>/<key2>..., got {args.wrap_in}')

    cfggen = ConfigGenerator(args.region, args, args.verbose)
    cfg = cfggen.generate_config()

    if args.output:
        conf_data = cfg.dict(exclude_unset=True, exclude_defaults=True, exclude_none=True)

        if args.wrap_in:
            for k in reversed(args.wrap_in.split('/')):
                conf_data = {k: conf_data}

        yaml_data = yaml.safe_dump(conf_data)
        if args.vault_ref:
            yaml_data = yaml_data.replace(VAULT_REF_REPLACEMENT,
                                          f'*vault(path: {vault_path}, field: {vault_field})')  # type: ignore
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
