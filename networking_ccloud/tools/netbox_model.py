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

from collections import Counter, defaultdict
from ipaddress import ip_network, ip_address
from itertools import groupby
import os
import re
from typing import Generator, Iterable, List, Tuple, Dict, Union, Any, Optional, Set


import pynetbox
from pynetbox.core.response import Record as NbRecord
from pynetbox.core.response import RecordSet as NbRecordSet


from networking_ccloud.tools.netbox_config_gen import ConfigGenerator, SWITCHGROUP_ROLE_VPOD, SWITCHGROUP_ROLE_NETPOD

NBR_DICT_T = Union[Dict[str, Any], NbRecord]


class CCFabricNetboxModeller():

    READ_API = pynetbox.api(ConfigGenerator.netbox_url)
    SUPPORTED_ROLES = {SWITCHGROUP_ROLE_VPOD, SWITCHGROUP_ROLE_NETPOD}

    PORT_CHANNEL_RANGE_BEGIN = 100

    CC_TENANT = READ_API.tenancy.tenants.get(slug='converged-cloud')
    CC_CONSOLE_ROLE = READ_API.ipam.roles.get(slug='cc-console')
    CC_MGMT_ROLE = READ_API.ipam.roles.get(slug='cc-management')
    CC_VMOTION_ROLE = READ_API.ipam.roles.get(slug='cc-vmotion')
    CC_BACKDOOR_MGMT_ROLE = READ_API.ipam.roles.get(slug='cc-backdoor-management')
    CC_MGMT_VRF = READ_API.ipam.vrfs.get(name='CC-MGMT')

    VENDOR_LAG_NAME = {
        'cisco': 'Port-channel',
        'arista': 'Port-Channel'
    }

    INFRA_VLANS = {
        'console': {'name': 'BB Console', 'role': CC_CONSOLE_ROLE.id, 'vid': 100},
        'mgmt': {'name': 'BB Mgmt', 'role': CC_MGMT_ROLE.id, 'vid': 101},
        'vmotion': {'name': 'BB vMotion', 'role': CC_VMOTION_ROLE.id, 'vid': 104},
        'backdoor': {'name': 'BB Backdoor Management', 'role': CC_BACKDOOR_MGMT_ROLE.id, 'vid': 106}
    }

    INFRA_NETWORKS = {
        'console': {'prefix_length': 26, 'position': 0},
        'mgmt': {'prefix_length': 26, 'position': 1},
        'vmotion': {'prefix_length': 27, 'position': -2},
        'backdoor': {'prefix_length': 27, 'position': -1},
    }

    def __init__(self, region: str, netbox_token: str, dry_run: bool):
        self.region = region
        self.api = pynetbox.api(ConfigGenerator.netbox_url, netbox_token)
        self.underlay_vrf = self.api.ipam.vrfs.get(name=f'EVPN-Underlay {self.region.upper()}')
        self.leaves_by_role = self.get_supported_pod_leaves()
        self.dry_run = dry_run

    def ensure_single_attribute(self, attributes: Iterable[str], devices: Iterable[NbRecord]) -> bool:
        v_set = set()
        for device in devices:
            v = device
            for attr in attributes:
                v = getattr(v, attr, None)
            if v is None:
                raise ValueError(f'Device {device.name}, attribute {attributes} are None')
            v_set.add(v)
        if len(v_set) > 1:
            return False
        return True

    def get_supported_pod_leaves(self) -> Dict[str, List[NbRecord]]:
        leaf_role = ConfigGenerator.leaf_role
        pod_roles = ConfigGenerator.pod_roles
        result = defaultdict(list)
        for device in self.api.dcim.devices.filter(region=self.region, role=leaf_role, status='active'):
            roles = {pod_roles.get(t.slug) for t in getattr(device, 'tags', [])}
            seq_no = ConfigGenerator.parse_ccloud_switch_number_resources(device.name)['seq_no']
            if roles and seq_no and len(roles.intersection(self.SUPPORTED_ROLES)) == 1:
                role = roles.intersection(self.SUPPORTED_ROLES).pop()
                result[role].append(device)
        return result

    def get_role_facing_interfaces(self, ifaces: NbRecordSet, role_slug: str) -> Generator[NbRecord, None, None]:
        for iface in ifaces:
            if not iface.connected_endpoint:
                continue
            device_role = getattr(iface.connected_endpoint.device, 'device_role')
            if not device_role or device_role.slug != role_slug:
                continue
            cluster = getattr(iface.connected_endpoint.device, 'cluster')
            if not cluster:
                continue
            if not ConfigGenerator.cluster_is_valid(cluster):
                continue
            yield iface

    def get_lag_name_for_ifaces(self, ifaces: Iterable[NbRecord], vendor: str) -> str:
        # Figure out LAG id, as a rule of thumb, we use BASE_LAG + interface_index
        # So Ethernet5/1 on Arista becomes BASE_LAG + 5
        # On Arista this is Ethernet5/1 -> 5
        # On Cisco it would be Ethernet1/5 -> 5
        # As we do not have any modular chassis as leaves and also no breakouts there we keep it simple

        rx = None
        if vendor.lower() == 'arista':
            rx = re.compile(r'Ethernet(?P<idx>\d+)(?:/(?P<slot>\d+))?')
        elif vendor.lower() == 'cisco':
            rx = re.compile(r'Ethernet(?P<slot>\d+)/(?P<idx>\d+)')
        else:
            raise ValueError(f'vendor: {vendor} is unsupported')

        iface_idxs = set()
        for iface in ifaces:
            m = rx.match(iface.name)
            if not m:
                raise ValueError(f'{iface.name} does not comply with pattern {rx.pattern}')
            iface_idxs.add(int(m.group('idx')))

        return f'{self.VENDOR_LAG_NAME[vendor.lower()]}{self.PORT_CHANNEL_RANGE_BEGIN + min(iface_idxs)}'

    def get_bb_mgmt_net(self, site: NbRecord, bb: int):
        candidate_nets = [x for x in self.api.ipam.prefixes.filter(role='cc-building-block',
                                                                   site_id=site.id, vrf_id=self.CC_MGMT_VRF.id)
                          if x.description.startswith(f'BB{bb:03d}')]
        if len(candidate_nets) != 1:
            raise ValueError(f'Could not find a mgmt supernet for BB{bb:03d} or found more than 1')
        return candidate_nets[0]

    def find_and_bundle_mlag_ports(self, gr_number, leaf_group: List[NbRecord],
                                   remote_role: str) -> List[Tuple[NBR_DICT_T, NBR_DICT_T]]:
        interfaces = set()
        lags_members = []
        for leaf in leaf_group:
            ifaces = self.api.dcim.interfaces.filter(device_id=leaf.id, connection_status=True)
            interfaces.update(self.get_role_facing_interfaces(ifaces, remote_role))

        def sorter(x):
            lag = getattr(x.connected_endpoint, 'lag', None)
            if lag:
                lag = lag.name
            return x.connected_endpoint.device.name, lag

        interfaces = sorted(interfaces, key=sorter)
        for (device, _), members_ifaces in groupby(interfaces, sorter):
            # ensure symmetric cabling
            members_ifaces = list(members_ifaces)
            if any(y != 2 for y in Counter(x.name for x in members_ifaces).values()):
                print(f'Asymmetric cabling in bb/np/st/{gr_number}, to {device}')
                continue
            # create both port-channels on the MLAG pair
            device_interface_map = defaultdict(list)
            for iface in members_ifaces:
                device_interface_map[iface.device].append(iface)
            for device, local_ifaces in device_interface_map.items():
                lags_members.append(tuple([self._bundle_ports(device, local_ifaces), local_ifaces]))
        return lags_members

    def _bundle_ports(self, device: NbRecord, ifaces: Iterable[NbRecord]) -> NBR_DICT_T:
        ifaces = list(ifaces)

        vendor = getattr(getattr(device.device_type, 'manufacturer', None), 'slug', None)
        try:
            lag_name = self.get_lag_name_for_ifaces(ifaces, vendor=vendor)
        except ValueError as e:
            raise ValueError(f'Could not get interface idx for {device.name}, {str(e)}')

        lag = self.api.dcim.interfaces.get(device_id=device.id, name=lag_name)
        if not lag:
            lag = {'name': lag_name, 'device': device.id, 'type': 'lag'}
            print(f'Creating LAG on {device.name}: {lag}')
            if not self.dry_run:
                lag = self.api.dcim.interfaces.create(lag)
        else:
            print(f'LAG {lag.name} on {device.name} already present')

        for iface in ifaces:

            def attach_lag():
                print(f'Assigning interface {iface.name}: {lag["name"]} on {device.name}')  # type: ignore
                if not self.dry_run:
                    iface.lag = lag.id  # type: ignore
                    iface.save()

            if iface.lag:
                if isinstance(lag, NbRecord) and iface.lag.id != iface.lag.id:
                    print(f'{iface.name} is already assigned to {iface.lag.name}'
                          f'but should but should be on {lag["name"]}, correcting')
                    attach_lag()
                elif isinstance(lag, dict) and iface.lag.name != lag['name']:
                    print(f'{iface.name} is already assigned to {iface.lag.name}'
                          f'but should but should be on {lag["name"]}, correcting')
                    attach_lag()
                else:
                    print(f'{iface.name} on {device.name} is already bundled into {lag["name"]}')  # type: ignore
            else:
                attach_lag()
        return lag

    def group_leaves_by(self, leaves: Iterable[NbRecord],
                        group_by: str) -> Generator[Tuple[int, List[NbRecord]], None, None]:
        sorter = lambda x: ConfigGenerator.parse_ccloud_switch_number_resources(x.name)[group_by]  # noqa e731
        leaves = sorted(leaves, key=sorter)
        for gr_attribute, gr in groupby(leaves, sorter):
            yield gr_attribute, list(gr)

    def create_vlan_group(self, site: NbRecord, bb: int) -> NBR_DICT_T:
        vgroup = self.api.ipam.vlan_groups.get(slug=f'cc-vpod{bb:03d}')
        if vgroup:
            print(f'VLAN group cc-vpod{bb:03d} exists')
            return vgroup
        vgroup = {'name': f'CC-vPOD{bb:03d}', 'slug': f'cc-vpod{bb:03d}', 'site': site.id}
        print(f'Creating VLAN group {vgroup}')
        if self.dry_run:
            return vgroup
        return self.api.ipam.vlan_groups.create(vgroup)

    def create_vlans(self, site: NbRecord, vlan_group: NBR_DICT_T) -> Dict[str, NBR_DICT_T]:
        vlans = dict()
        vlan_group_id = vlan_group.id if isinstance(vlan_group, NbRecord) else vlan_group['name']
        for name, vlan in self.INFRA_VLANS.items():
            nb_vlan = None
            if isinstance(vlan_group, NbRecord):
                # For simplification we assume that without a proper VLAN group there cannot be a
                # vlan. Even if there were, we had no way to identify it.
                nb_vlan = self.api.ipam.vlans.get(group_id=vlan_group_id, tenant_id=self.CC_TENANT.id,
                                                  name=vlan['name'], role_id=vlan['role'])
            if not nb_vlan:
                nb_vlan = dict(site=site.id, group=vlan_group_id,
                               tenant=self.CC_TENANT.id, status='active', **vlan)
                print(f'Creating VLAN {nb_vlan}')
                if not self.dry_run:
                    nb_vlan = self.api.ipam.vlans.create(nb_vlan)
            else:
                print(f'{name} vlan is already present in {vlan_group["slug"]}')
            vlans[name] = nb_vlan
        return vlans

    def attach_infra_vlans_to_iface(self, vlans: Iterable[NBR_DICT_T], iface: NBR_DICT_T):
        _types = {isinstance(v, NbRecord) for v in vlans}
        if len(_types) != 1:
            raise ValueError(f'List of vlans has more than 1 type {vlans}')
        if _types.pop():
            vlan_ids = [v.id for v in vlans]  # type: ignore
        else:
            vlan_ids = [v['name'] for v in vlans]

        self._check_set_attr(iface, mode='tagged', tagged_vlans=vlan_ids)

    def create_prefix_on_vlans(self, vlans: Dict[str, NBR_DICT_T],
                               bb_net: NbRecord, site: NbRecord) -> Dict[str, NBR_DICT_T]:
        prefixes = dict()
        for name, vlan in vlans.items():
            prefix_conf = self.INFRA_NETWORKS[name]
            bb_ip_network = ip_network(bb_net.prefix)
            position = prefix_conf['position']
            desired_prefix = str(list(bb_ip_network.subnets(new_prefix=prefix_conf['prefix_length']))[position])
            vlan_id = vlan.id if isinstance(vlan, NbRecord) else vlan['name']
            prefix = None
            if isinstance(vlan, NbRecord):
                # If we have no vlan, we assume that there is also no prefix. This is not quite correct as the
                # the prefix could be existing but dangling.
                # FIXME: take care of dangling prefix
                prefix = self.api.ipam.prefixes.get(vrf_id=self.CC_MGMT_VRF.id, tenant_id=self.CC_TENANT.id,
                                                    site_id=site.id, vlan_id=vlan_id, prefix=desired_prefix)
            if not prefix:
                vlan_role = vlan.role.id if isinstance(vlan, NbRecord) else vlan['role']  # type: ignore
                prefix = {
                    'family': 4, 'vrf': self.CC_MGMT_VRF.id, 'tenant': self.CC_TENANT.id,
                    'prefix': desired_prefix, 'site': site.id, 'vlan': vlan_id,
                    'role': vlan_role, 'status': 'active', 'is_pool': False}
                print(f'Creating prefix {prefix}')
                if not self.dry_run:
                    prefix = self.api.ipam.prefixes.create(prefix)
            else:
                print(f'Prefix {desired_prefix} already present')
            prefixes[name] = prefix
        return prefixes

    def _get_create_ip(self, ip: str, tenant: NbRecord, vrf: NbRecord, role: str) -> NBR_DICT_T:
        addr = self.api.ipam.ip_addresses.get(address=ip, role=role, tenant_id=tenant.id,
                                              vrf_id=vrf.id, assigned_object_id=None)
        if addr:
            addr.status = 'active'
        if addr and not self.dry_run:
            addr.save()
        if not addr:
            addr = dict(address=ip, role=role, tenant_id=tenant.id, vrf_id=vrf.id, status='active',
                        family=4)
            print(f'Creating IP address {addr}')
            if not self.dry_run:
                addr = self.api.ipam.ip_addresses.create(addr)
        return addr

    def _get_create_interface(self, device: NbRecord, iface_name: str, iface_type: str) -> NBR_DICT_T:
        iface = self.api.dcim.interfaces.get(device_id=device.id, name=iface_name)
        if not iface:
            iface = dict(name=iface_name, device=device.id, type=iface_type)
            print(f'Creating {iface_type} interface on {device.name}: {iface}')
            if not self.dry_run:
                iface = self.api.dcim.interfaces.create(iface)
        return iface

    def _check_set_attr(self, item: NBR_DICT_T, **attrs) -> NBR_DICT_T:

        def get_value_or_sorted_list(obj, attr, default=None):
            if isinstance(obj, list):
                return sorted([getattr(x, attr, default) for x in obj])
            return getattr(obj, attr, default)

        changed = False
        for attr, value in attrs.items():
            if isinstance(value, list):
                value = sorted(value)
            # if the item is a Record, match on either id or value
            if isinstance(item, NbRecord):
                item_val = getattr(item, attr)
                if item_val:
                    if item_val == value:
                        continue
                    if get_value_or_sorted_list(item_val, 'id', None) == value:
                        continue
                    if get_value_or_sorted_list(item_val, 'name', None) == value:
                        continue
                    if get_value_or_sorted_list(item_val, 'value', None) == value:
                        continue
                setattr(item, attr, value)
            else:
                if value != item.get(attr, None):
                    continue
                item[attr] = value
            print(f'On {item} setting attribute {attr} = {value}')
            changed = True
        if not self.dry_run and isinstance(item, NbRecord) and changed:
            item.save()
        return item

    def attach_svi_to_switch(self, switch: NbRecord, vlan: NBR_DICT_T,
                             prefix: NBR_DICT_T) -> Tuple[NBR_DICT_T, NBR_DICT_T]:
        ip_addr_prefix = ip_network(prefix['prefix'])
        gateway_addr = f'{next(ip_addr_prefix.hosts())}/{ip_addr_prefix.prefixlen}'
        vlan_vid = vlan["vid"]
        # FIXME: Warn and maybe handle for inconsistent values, like vid, gateway
        svi = self._get_create_interface(switch, f'Vlan{vlan_vid}', 'virtual')
        untagged_vlan = vlan.id if isinstance(vlan, NbRecord) else vlan['name']
        self._check_set_attr(svi, mode='access', untagged_vlan=untagged_vlan)
        bound_ip = dict()
        if isinstance(svi, NbRecord):
            bound_ip = self.api.ipam.ip_addresses.get(interface_id=svi.id)
        if not bound_ip:
            bound_ip = self._get_create_ip(gateway_addr, self.CC_TENANT, self.CC_MGMT_VRF, 'anycast')
            svi_name = svi['name']  # type: ignore
            svi_id = svi.id if isinstance(svi, NbRecord) else svi_name
            self._check_set_attr(bound_ip, assigned_object_type='dcim.interface', assigned_object_id=svi_id)
        else:
            self._check_set_attr(bound_ip, vrf=self.CC_MGMT_VRF.id, tenant=self.CC_TENANT.id)
        return svi, bound_ip

    def create_attach_vtep_loopback(self, switch: NbRecord):
        iface_name = 'Loopback1'
        iface = self._get_create_interface(switch, iface_name, 'virtual')
        bound_ip = dict()
        if isinstance(iface, NbRecord):
            bound_ip = self.api.ipam.ip_addresses.get(interface_id=iface.id)
        if not bound_ip:
            numbered_res = ConfigGenerator.parse_ccloud_switch_number_resources(switch.name)
            addr = str(ip_address(f"{numbered_res['az_no']}.{numbered_res['pod']}.{numbered_res['switchgroup_no']}.0"))
            bound_ip = self._get_create_ip(f'{addr}/32', self.CC_TENANT, self.underlay_vrf, 'anycast')
            _id = iface.id if isinstance(iface, NbRecord) else iface_name
            self._check_set_attr(bound_ip, assigned_object_type='dcim.interface', assigned_object_id=_id)
        else:
            self._check_set_attr(bound_ip, vrf=self.underlay_vrf.id, tenant=self.CC_TENANT.id)

    def create_attach_bgpsrc(self, switch: NbRecord):
        iface_name = 'Loopback0'
        iface = self._get_create_interface(switch, iface_name, 'virtual')
        bound_ip = dict()
        if isinstance(iface, NbRecord):
            bound_ip = self.api.ipam.ip_addresses.get(interface_id=iface.id)
        if not bound_ip:
            numbered_res = ConfigGenerator.parse_ccloud_switch_number_resources(switch.name)
            addr = str(ip_address(f"{numbered_res['az_no']}.{numbered_res['pod']}."
                                  f"{numbered_res['switchgroup_no']}.{numbered_res['leaf_no']}"))
            bound_ip = self._get_create_ip(f'{addr}/32', self.CC_TENANT, self.underlay_vrf, 'loopback')
            _id = iface.id if isinstance(iface, NbRecord) else iface_name
            self._check_set_attr(bound_ip, assigned_object_type='dcim.interface', assigned_object_id=_id)
        else:
            self._check_set_attr(bound_ip, vrf=self.underlay_vrf.id, tenant=self.CC_TENANT.id)

    def model_bbs(self, limit_bbs: Optional[Set[int]] = None):
        for bb, gr in self.group_leaves_by(self.leaves_by_role[SWITCHGROUP_ROLE_VPOD], 'seq_no'):
            if limit_bbs and bb not in limit_bbs:
                continue
            if not self.ensure_single_attribute(('site', 'slug'), gr):
                print(f'BB{bb} switches {gr} have different sites, skipping')
                continue

            site = gr[0].site
            vgroup = self.create_vlan_group(site, bb)
            vlans = self.create_vlans(site, vgroup)
            mgmt_net = self.get_bb_mgmt_net(site, bb)
            prefixes = self.create_prefix_on_vlans(vlans, mgmt_net, site)

            for switch in gr:
                self.create_attach_vtep_loopback(switch)
                self.create_attach_bgpsrc(switch)
                for vlan_name, vlan in vlans.items():
                    self.attach_svi_to_switch(switch, vlan, prefixes[vlan_name])
            lags = self.find_and_bundle_mlag_ports(bb, gr, 'server')
            for lag, _ in lags:
                self.attach_infra_vlans_to_iface(vlans.values(), lag)

    def model_neutron_routers(self, limit_nps: Optional[Set[int]] = None):
        for np, gr in self.group_leaves_by(self.leaves_by_role[SWITCHGROUP_ROLE_NETPOD], 'seq_no'):
            if limit_nps and np not in limit_nps:
                continue
            if not self.ensure_single_attribute(('site', 'slug'), gr):
                print(f'Np{np} switches {gr} have different sites, skipping')
                continue
            lags = self.find_and_bundle_mlag_ports(np, gr, 'neutron-router')
            for lag, members in lags:
                for member in members:
                    # We only care about port-channel 1 at the moment cause that's the one OS binds ports to
                    ignore_tag = list(ConfigGenerator.ignore_tags)[0]
                    if member.connected_endpoint.lag.name != 'Port-channel1':
                        if isinstance(lag, dict):
                            print(f'Adding ignore-tag to {lag["name"]} on {lag["device"]}.')
                            break
                        if ignore_tag in {x.slug for x in lag.tags}:
                            break
                        print(f'Adding ignore-tag to {lag.name} on {lag.device.name}.')
                        if not self.dry_run:
                            lag.tags.append({'slug': ignore_tag})
                            lag.save()
                    break


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--region", required=True)
    parser.add_argument("-s", "--shell", action="store_true")
    parser.add_argument("-t", "--netbox-token", help='Netbox self.api token, can also use ENV: NETBOX_TOKEN')
    parser.add_argument('-l', "--limit-bb", nargs='*', type=int, help='Only run for some bb', default=list())
    parser.add_argument('-n', "--limit-np", nargs='*', type=int, help='Only run for some np', default=list())
    parser.add_argument('-d', "--dry-run", help='Do not actually change something, just log', action="store_true")

    args = parser.parse_args()

    if not os.environ.get('NETBOX_TOKEN') and not args.netbox_token:
        print('Either --netbox-token must be supplied or ENV: NETBOX_TOKEN must be set.')
        exit(2)

    # arg superseeds ENV
    netbox_token = args.netbox_token if args.netbox_token else os.environ.get('NETBOX_TOKEN')
    modeller = CCFabricNetboxModeller(args.region, netbox_token, args.dry_run)

    if args.shell:
        import IPython
        IPython.embed()

    modeller.model_bbs(limit_bbs=set(args.limit_bb))
    modeller.model_neutron_routers(limit_nps=args.limit_np)


if __name__ == '__main__':
    main()