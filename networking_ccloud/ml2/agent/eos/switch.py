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

from operator import attrgetter
import re
from typing import List, Optional
import uuid

from oslo_log import log as logging

from networking_ccloud.common import constants as cc_const
from networking_ccloud.ml2.agent.common.gnmi import CCGNMIClient
from networking_ccloud.ml2.agent.common import messages as agent_msg
from networking_ccloud.ml2.agent.common.messages import OperationEnum as Op
from networking_ccloud.ml2.agent.common.switch import SwitchBase


LOG = logging.getLogger(__name__)


# Sysdb/routing/bgp/macvrf/config/vlan.3087 or
# Sysdb/routing/bgp/macvrf/config/vlan.3087/importRemoteDomainRtList
EVPN_PREFIX_RE = re.compile(r"^Sysdb/routing/bgp/macvrf/config/vlan\.(?P<vlan>\d+)(:?/(?P<suffix>[^/]+))?$")
UUID_RE = re.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class EOSGNMIPaths:
    VLANS = "network-instances/network-instance[name=default]/vlans"
    VLAN = "network-instances/network-instance[name=default]/vlans/vlan[vlan-id={vlan}]"

    VXMAPS = "interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis"
    VXMAP_VLAN = ("interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis"
                  "/vlan-to-vni[vlan={vlan}]")
    VRF_VXMAPS = "interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vrf-to-vnis"
    VRF_VXMAP_VRF = ("interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vrf-to-vnis/"
                     "vrf-to-vni[vrf={vrf}]")

    EVPN_INSTANCES = "arista/eos/arista-exp-eos-evpn:evpn/evpn-instances"
    EVPN_INSTANCE = "arista/eos/arista-exp-eos-evpn:evpn/evpn-instances/evpn-instance[name={vlan}]"
    EVPN_INSTANCES_VIA_SYSDB = "eos_native:Sysdb/routing/bgp/macvrf/config"
    PROTO_BGP = "network-instances/network-instance[name=default]/protocols/protocol[name=BGP]"
    NETWORK_INSTANCES = "network-instances"
    NETWORK_INSTANCE_IFACES = "network-instances/network-instance[name={vrf}]/interfaces"
    BGP_VRF_AGGREGATES = ("network-instances/network-instance[name={vrf}]/protocols/protocol[name=BGP]/"
                          "bgp/global/afi-safis/afi-safi[afi-safi-name=openconfig-bgp-types:IPV4_UNICAST]/"
                          "aggregate-addresses")
    BGP_VRF_AGGREGATE_PREFIX = ("network-instances/network-instance[name={vrf}]/protocols/protocol[name=BGP]/"
                                "bgp/global/afi-safis/afi-safi[afi-safi-name=openconfig-bgp-types:IPV4_UNICAST]/"
                                "aggregate-addresses/aggregate-address[aggregate-address={prefix}]")
    PREFIX_LISTS = "routing-policy/defined-sets/prefix-sets"
    PREFIX_LIST = "routing-policy/defined-sets/prefix-sets/prefix-set[name={name}]"
    PREFIX_LIST_PREFIX = ("routing-policy/defined-sets/prefix-sets/prefix-set[name={name}]/"
                          "prefixes/prefix[ip-prefix={prefix}]")

    IFACES = "interfaces"
    IFACE = "interfaces/interface[name={name}]"
    IFACE_ETH = "interfaces/interface[name={iface}]/ethernet"
    IFACE_VTRUNKS = "interfaces/interface[name={iface}]/ethernet/switched-vlan/config/trunk-vlans"
    IFACE_NATIVE_VLAN = "interfaces/interface[name={iface}]/ethernet/switched-vlan/config/native-vlan"
    IFACE_VTRANS = "interfaces/interface[name={iface}]/ethernet/switched-vlan/vlan-translation"
    IFACE_VTRANS_EGRESS = ("interfaces/interface[name={iface}]/ethernet/switched-vlan/vlan-translation/"
                           "egress[translation-key={vlan}]")
    IFACE_VTRANS_INGRESS = ("interfaces/interface[name={iface}]/ethernet/switched-vlan/vlan-translation/"
                            "ingress[translation-key={vlan}]")
    IFACE_PC = "interfaces/interface[name={iface}]/aggregation"
    IFACE_PC_VTRUNKS = "interfaces/interface[name={iface}]/aggregation/switched-vlan/config/trunk-vlans"
    IFACE_PC_NATIVE_VLAN = "interfaces/interface[name={iface}]/aggregation/switched-vlan/config/native-vlan"
    IFACE_PC_VTRANS = "interfaces/interface[name={iface}]/aggregation/switched-vlan/vlan-translation"
    IFACE_PC_VTRANS_EGRESS = ("interfaces/interface[name={iface}]/aggregation/switched-vlan/vlan-translation/"
                              "egress[translation-key={vlan}]")
    IFACE_PC_VTRANS_INGRESS = ("interfaces/interface[name={iface}]/aggregation/switched-vlan/vlan-translation/"
                               "ingress[translation-key={vlan}]")
    IFACE_IPS_VIA_SYSDB = "eos_native:Sysdb/ip/config/ipIntfConfig"
    IFACE_VIRTUAL_ADDRESS = "interfaces/interface[name={name}]/arista-varp/virtual-address"


class EOSSetConfig:
    def __init__(self):
        self.delete = []
        self.replace = []
        self.update = []
        self.update_cli = []

    def get_list(self, op):
        if op == Op.add:
            return self.update
        elif op == Op.replace:
            return self.replace
        else:
            raise ValueError("Only available for add/replace")


class EOSSwitch(SwitchBase):
    # PL-CC-CLOUD02 | PL-CC-CLOUD02-A | PL-CC-CLOUD02-EXTERNAL | PL-CC-CLOUD02-A-EXTERNAL
    PREFIX_LIST_RE = re.compile("PL-(?P<vrf>.*?)(?:-(?P<az>[A-Z]))?(?:-(?P<external>EXTERNAL))?$")

    @classmethod
    def get_platform(cls):
        return cc_const.PLATFORM_EOS

    def login(self):
        self._api = CCGNMIClient(switch_name=self.name, host=self.host, port=6030,
                                 username=self.user, password=self._password, platform=self.get_platform(),
                                 insecure=False, skip_verify=True)
        self._api.connect()

    @staticmethod
    def _compress_vlan_list(vlan_ints: List[int]) -> List[str]:
        """Merge all subsequent vlans to a range seperated by ".."

        E.g. [1,3,4,5,6,8] --> ["1", "3..6", "8"]
        """
        vlan_ints.sort()
        first_vlan = last_vlan = None
        result = []

        def add_elem():
            if first_vlan is None:
                return
            if first_vlan < last_vlan:
                result.append(f"{first_vlan}..{last_vlan}")
            else:
                result.append(f"{first_vlan}")

        for vlan in vlan_ints:
            if last_vlan is None or last_vlan + 1 < vlan:
                add_elem()
                first_vlan = last_vlan = vlan
            else:
                last_vlan = vlan
        add_elem()

        return result

    def _get_switch_status(self):
        # FIXME: we can get this without cli, but sometimes the chassis/model seems to be empty
        #        once we figure out when this is the case we can use the code below instead of cli:/show version
        # ver, model, uptime_ns = self.api.get(path=['system/config/hostname',
        #                                            'components/component[name=Chassis]/state/part-no',
        #                                            'system/state/boot-time'])
        # uptime = time.time() - uptime_ns / 10 ** 9
        ver = self.api.get(path=["cli:/show version"])

        return {
            'name': self.name,
            'host': self.host,
            'api_user': self.user,
            'version': ver['version'],
            'model': ver['modelName'],
            'uptime': ver['uptime'],
        }

    def get_vlan_config(self) -> List[agent_msg.Vlan]:
        swdata = self.api.get(EOSGNMIPaths.VLANS)["openconfig-network-instance:vlan"]
        vlans = []
        for v in swdata:
            if v['vlan-id'] not in self.managed_vlans:
                continue
            vname = v['config']['name']
            if re.match("^[0-9a-f]{32}$", vname):
                # name looks like a uuid --> convert it back to one with "-"
                vname = str(uuid.UUID(vname))
            vlans.append(agent_msg.Vlan(vlan=v['vlan-id'], name=vname))
        vlans.sort()
        return vlans

    def get_all_managed_vlan_ids_on_switch(self):
        vlans_on_switch = self.api.get(f"{EOSGNMIPaths.VLANS}/vlan/vlan-id", single=False)

        return set(vlans_on_switch) & set(self.managed_vlans)

    def _make_vlan_config(self, config_req: EOSSetConfig, vlans: Optional[List[agent_msg.Vlan]], operation: Op) -> None:
        if vlans is None:
            return

        if operation in (Op.add, Op.replace):
            wanted_vlans = []
            if operation == Op.replace:
                # remove unwanted vlans
                vlans_to_remove = self.get_all_managed_vlan_ids_on_switch() - set(v.vlan for v in vlans)
                for vlan in sorted(vlans_to_remove):
                    LOG.debug("Removing stale vlan %s from %s (%s) on config replace", vlan, self.name, self.host)
                    vpath = EOSGNMIPaths.VLAN.format(vlan=vlan)
                    config_req.delete.append(vpath)

            for vlan in vlans:
                vlan_name = vlan.name
                if UUID_RE.match(vlan_name):
                    vlan_name = vlan_name.replace("-", "")
                vcfg = {'vlan-id': vlan.vlan, 'config': {'name': vlan_name, 'vlan-id': vlan.vlan}}
                wanted_vlans.append(vcfg)
            vlan_cfg = (EOSGNMIPaths.VLANS, {'vlan': wanted_vlans})
            config_req.update.append(vlan_cfg)
        else:
            for vlan in vlans:
                vpath = EOSGNMIPaths.VLAN.format(vlan=vlan.vlan)
                config_req.delete.append(vpath)

    def get_vxlan_mappings(self, with_unmanaged=False) -> List[agent_msg.VXLANMapping]:
        swdata = self.api.get(EOSGNMIPaths.VXMAPS)['arista-exp-eos-vxlan:vlan-to-vni']
        vxlan_maps = [agent_msg.VXLANMapping(vni=v['vni'], vlan=v['vlan']) for v in swdata
                      if with_unmanaged or v['vlan'] in self.managed_vlans]
        vxlan_maps.sort()
        return vxlan_maps

    def _make_vxlan_mapping_config(self, config_req: EOSSetConfig, vxlan_maps: Optional[List[agent_msg.VXLANMapping]],
                                   operation: Op) -> None:
        if vxlan_maps is None:
            return

        curr_maps = self.get_vxlan_mappings(with_unmanaged=True)
        if operation in (Op.add, Op.replace):
            if operation == Op.replace:
                # remove all mappings that are managed by us but no longer needed
                vmaps_to_remove = set(m.vlan for m in curr_maps) - set(m.vlan for m in vxlan_maps)
                vmaps_to_remove &= self.managed_vlans
                curr_maps = [m for m in curr_maps if m.vlan not in vmaps_to_remove]
                for vlan in vmaps_to_remove:
                    LOG.debug("Removing stale vlan mapping for vlan %s from %s (%s) on config replace",
                              vlan, self.name, self.host)
                    config_req.delete.append(EOSGNMIPaths.VXMAP_VLAN.format(vlan=vlan))

            # delete all mappings for VNIs we want to repurpose, but are used by a different vlan
            for curr_map in curr_maps:
                for os_map in vxlan_maps:
                    if os_map.vni == curr_map.vni and os_map.vlan != curr_map.vlan:
                        LOG.warning("Removing stale vxlan map <vlan %s vni %s> in favor of <vlan %s vni %s> "
                                    "on switch %s (%s)",
                                    curr_map.vlan, curr_map.vni, os_map.vlan, os_map.vni, self.name, self.host)
                        del_map = EOSGNMIPaths.VXMAP_VLAN.format(vlan=curr_map.vlan)
                        config_req.delete.append(del_map)

            mapcfgs = [{'vlan': vmap.vlan, 'vni': vmap.vni} for vmap in vxlan_maps]
            config_req.update.append((EOSGNMIPaths.VXMAPS, {'vlan-to-vni': mapcfgs}))
        else:
            # delete vlan mapping only if it has the right vni
            for os_map in vxlan_maps:
                for curr_map in curr_maps:
                    if curr_map.vlan == os_map.vlan:
                        if curr_map.vni == os_map.vni:
                            config_req.delete.append(EOSGNMIPaths.VXMAP_VLAN.format(vlan=curr_map.vlan))
                        else:
                            LOG.warning("Not deleting vlan %s from switch %s (%s), as it points to vni %s "
                                        "(delete requested vni %s)",
                                        curr_map.vlan, self.name, self.host, curr_map.vni, os_map.vni)
                        break
                else:
                    LOG.warning("VLAN %s not found on switch %s (%s), not deleting it",
                                os_map.vlan, self.name, self.host)

    def get_bgp_evpn_extented_config_from_sysdb(self):
        curr_insts = {}
        sysdb_entries = self.api.get(EOSGNMIPaths.EVPN_INSTANCES_VIA_SYSDB, unpack=False)['notification']
        for entry in sysdb_entries:
            m = EVPN_PREFIX_RE.match(entry['prefix'])
            if not m:
                LOG.warning("Unepxected paths %s when fetching vlan instances on %s (%s)",
                            entry['prefix'], self.name, self.host)
                continue

            inst = curr_insts.setdefault(int(m.group('vlan')),
                                         {'remote-rd': None, 'remote-rt-imports': [], 'remote-rt-exports': []})

            suffix = m.group('suffix')
            if suffix in ('importRemoteDomainRtList', 'exportRemoteDomainRtList'):
                for subentry in entry['update']:
                    val = subentry['path']
                    # FIXME: convert the value
                    try:
                        val = agent_msg.validate_route_target(val)
                        if suffix == 'importRemoteDomainRtList':
                            inst['remote-rt-imports'].append(val)
                        else:
                            inst['remote-rt-exports'].append(val)
                    except ValueError as e:
                        LOG.error("Invalid evpn remote RT value %s path %s from sysdb on %s (%s): %s",
                                  val, entry['prefix'], self.name, self.host, e)
            elif suffix is None:
                # find rd evpn domain all
                rd_no = None
                rd_valid = False
                for subentry in entry['update']:
                    if subentry['path'] == 'remoteRd/rdNboInternal':
                        rd_no = subentry['val']
                    elif subentry['path'] == 'remoteRd/valid':
                        rd_valid = subentry['val']
                if rd_valid:
                    # rd_no is in network byte-order, obviously
                    rd_no = int.from_bytes(rd_no.to_bytes(8, 'big'), 'little')

                    # validate_route_target also works for route-distinguisher in this case
                    # only the error message will look somewhat weird, but as this is only temporary...
                    try:
                        inst['remote-rd'] = agent_msg.validate_route_distinguisher(rd_no)
                    except ValueError as e:
                        LOG.error("Invalid evpn remote RD value %s path %s from sysdb on %s (%s): %s ",
                                  rd_no, entry['prefix'], self.name, self.host, e)

        return curr_insts

    def get_bgp_vlan_config(self) -> List[agent_msg.BGPVlan]:
        bgp_vlans = []
        curr_evpn_ext_conf = self.get_bgp_evpn_extented_config_from_sysdb()
        curr_bgp_vlans = self.api.get(EOSGNMIPaths.EVPN_INSTANCES)["arista-exp-eos-evpn:evpn-instance"]
        for entry in curr_bgp_vlans:
            if not entry['name'].isdecimal():
                LOG.warning("Could not match bgp vpn instance name '%s' to a vlan", entry['name'])
                continue

            vlan = int(entry['name'])
            if vlan not in self.managed_vlans:
                continue

            rd = None
            rd_evpn_domain_all = False
            rt_imports_evpn = []
            rt_exports_evpn = []

            # first look in X
            if vlan in curr_evpn_ext_conf:
                ext_conf = curr_evpn_ext_conf[vlan]
                rt_imports_evpn = ext_conf['remote-rt-imports']
                rt_exports_evpn = ext_conf['remote-rt-exports']
                rd = ext_conf['remote-rd']
                if rd:
                    rd_evpn_domain_all = True

            rtdata = entry.get('route-target', {'config': {}})['config']
            if not rd:
                rd = entry['config'].get('route-distinguisher')  # FIXME: this is bad. need to distinguish

            if not rd:
                LOG.debug("BGP Vlan %s on switch %s has no rd, skipping it", entry['name'], self.name)
                continue

            bv = agent_msg.BGPVlan(rd=rd, vlan=vlan,
                                   rt_imports=rtdata.get('import', []), rt_exports=rtdata.get('export', []),
                                   # eos_native:Sysdb/routing/bgp/macvrf/config/vlan.2323
                                   rd_evpn_domain_all=rd_evpn_domain_all,
                                   rt_imports_evpn=rt_imports_evpn,
                                   rt_exports_evpn=rt_exports_evpn)
            # FIXME: redistribute learned flag? does not fit in our internal data structure
            bgp_vlans.append(bv)
        return bgp_vlans

    def get_vrf_prefix_lists(self):
        """Get BGP VRF prefix lists, keyed by vrf and then (az_local, ext_announcable)"""
        prefix_lists = {}
        for pl in self.api.get(EOSGNMIPaths.PREFIX_LISTS)['openconfig-routing-policy:prefix-set']:
            m = self.PREFIX_LIST_RE.match(pl['name'])
            if not m:
                continue

            prefixes = []
            for prefix in pl.get('prefixes', {}).get('prefix', []):
                if prefix.get('masklength-range') != 'exact':
                    # NOTE: we currently only handle entries that have an exact match
                    continue
                prefixes.append(prefix['ip-prefix'])

            if prefixes:
                vrf = prefix_lists.setdefault(m.group('vrf'), {})
                vrf[(bool(m.group('az')), bool(m.group('external')))] = prefixes

        return prefix_lists

    def get_bgp_vrf_config(self) -> List[agent_msg.BGPVRF]:
        bgp_vrfs = []

        # get prefix lists and sort them by VRF
        prefix_lists = self.get_vrf_prefix_lists()

        for inst in self.api.get(EOSGNMIPaths.NETWORK_INSTANCES)['openconfig-network-instance:network-instance']:
            if inst['config']['type'] != 'openconfig-network-instance-types:L3VRF':
                continue
            for inst_bgp in inst['protocols']['protocol']:
                if inst_bgp['name'] == 'BGP':
                    break
            else:
                # VRFs without BGP do not interest us
                continue

            # get aggregates
            aggregates = []
            agg_rm_az_local = self.gen_route_map_name(inst['name'], True)
            agg_rm_regional = self.gen_route_map_name(inst['name'], False)
            for afi_safi in inst_bgp['bgp']['global']['afi-safis']['afi-safi']:
                if afi_safi['afi-safi-name'] == 'openconfig-bgp-types:IPV4_UNICAST':
                    if 'arista-bgp-augments:aggregate-addresses' in afi_safi:
                        for agg in afi_safi['arista-bgp-augments:aggregate-addresses']['aggregate-address']:
                            if agg['config']['attribute-map'] not in (agg_rm_az_local, agg_rm_regional):
                                continue

                            az_local = agg['config']['attribute-map'] == agg_rm_az_local
                            bgpvrfagg = agent_msg.BGPVRFAggregate(network=agg['aggregate-address'],
                                                                  az_local=az_local)
                            aggregates.append(bgpvrfagg)

            # get networks from prefix lists
            networks = []
            for (az_local, ext_announcable), prefixes in prefix_lists.get(inst['name'], {}).items():
                for prefix in prefixes:
                    networks.append(agent_msg.BGPVRFNetwork(network=prefix, az_local=az_local,
                                                            ext_announcable=ext_announcable))

            bgpvrf = agent_msg.BGPVRF(name=inst['name'],
                                      aggregates=aggregates, networks=networks)
            bgp_vrfs.append(bgpvrf)
        return bgp_vrfs

    def get_bgp_config(self) -> agent_msg.BGP:
        bgp_asn = self.api.get(f"{EOSGNMIPaths.PROTO_BGP}/bgp/global/config/as")
        bgp = agent_msg.BGP(asn=bgp_asn, asn_region=self.asn_region, vlans=self.get_bgp_vlan_config())
        bgp.vrfs = self.get_bgp_vrf_config()
        return bgp

    def gen_prefix_list_name(self, vrf_name, az_local, ext_announcable):
        name = f"PL-{vrf_name}"
        if az_local:
            name += f"-{self.az_suffix.upper()}"
        if ext_announcable:
            name += "-EXTERNAL"
        return name

    def gen_route_map_name(self, vrf_name, az_local):
        az_data = f"{self.az_suffix.upper()}-" if az_local else ""
        return f"RM-{vrf_name}-{az_data}AGGREGATE"

    def _make_bgp_vrf_config(self, config_req: EOSSetConfig, bgp_vrfs: Optional[List[agent_msg.BGPVRF]], operation: Op):
        if bgp_vrfs is None:
            return

        device_vrfs = None
        if operation == Op.replace:
            device_vrfs = self.get_bgp_vrf_config()

        for bgp_vrf in bgp_vrfs:
            if operation in (Op.add, Op.replace):
                if operation == Op.replace:
                    # remove all aggregates that are not required anymore
                    for device_vrf in device_vrfs:
                        if device_vrf.name == bgp_vrf.name:
                            break
                    else:
                        device_vrf = None

                    if device_vrf:
                        cfg_aggs = [agg.network for agg in bgp_vrf.aggregates or []]
                        for device_agg in device_vrf.aggregates or []:
                            if device_agg.network not in cfg_aggs:
                                delete_req = EOSGNMIPaths.BGP_VRF_AGGREGATE_PREFIX.format(
                                    vrf=bgp_vrf.name, prefix=device_agg.network)
                                config_req.delete.append(delete_req)

                # add aggregates
                aggregates = [{'aggregate-address': agg.network,
                               'config': {'aggregate-address': agg.network,
                                          'attribute-map': self.gen_route_map_name(bgp_vrf.name, agg.az_local)}}
                              for agg in bgp_vrf.aggregates or []]
                config_req.update.append((EOSGNMIPaths.BGP_VRF_AGGREGATES.format(vrf=bgp_vrf.name),
                                          {'aggregate-address': aggregates}))

                # manage prefix lists
                # generate all prefix lists that we have, as on replace we'd clear all out that have no data
                prefix_lists = {self.gen_prefix_list_name(bgp_vrf.name, az_local, ext_announcable): []
                                for az_local, ext_announcable in [(False, False), (False, True),
                                                                  (True, False), (True, True)]}
                for net in bgp_vrf.networks or []:
                    pl_name = self.gen_prefix_list_name(bgp_vrf.name, net.az_local, net.ext_announcable)
                    prefix_lists[pl_name].append({'ip-prefix': net.network, 'masklength-range': 'exact',
                                                  'config': {'ip-prefix': net.network, 'masklength-range': 'exact'}})
                for pl_name, prefixes in prefix_lists.items():
                    pl_config = {
                        'name': pl_name,
                        'config': {'name': pl_name},
                        'prefixes': {'prefix': prefixes},
                    }
                    config_req.get_list(operation).append((EOSGNMIPaths.PREFIX_LIST.format(name=pl_name),
                                                           pl_config))
            else:
                # delete
                for net in bgp_vrf.networks:
                    pl_name = self.gen_prefix_list_name(bgp_vrf.name, net.az_local, net.ext_announcable)
                    delete_req = EOSGNMIPaths.PREFIX_LIST_PREFIX.format(name=pl_name, prefix=net.network)
                    config_req.delete.append(delete_req)

                for agg in bgp_vrf.aggregates:
                    # NOTE: We're deleting regardless of route-map here
                    delete_req = EOSGNMIPaths.BGP_VRF_AGGREGATE_PREFIX.format(vrf=bgp_vrf.name,
                                                                              prefix=agg.network)
                    config_req.delete.append(delete_req)

    def _make_bgp_config(self, config_req: EOSSetConfig, bgp: Optional[agent_msg.BGP], operation: Op) -> None:
        if bgp:
            if bgp.vlans:
                self._make_bgp_vlans_config(config_req, bgp, operation)
            if bgp.vrfs:
                self._make_bgp_vrf_config(config_req, bgp.vrfs, operation)

    def _make_bgp_vlans_config(self, config_req: EOSSetConfig, bgp: Optional[agent_msg.BGP], operation: Op):
        if operation in (Op.add, Op.replace):
            bgp_vlans_on_switch = None
            if operation == Op.replace:
                # remove stale bgp vlans / evpn instances
                bgp_vlans_on_switch = self.get_bgp_vlan_config()
                bgp_vlans_to_remove = set(bv.vlan for bv in bgp_vlans_on_switch) - set(bv.vlan for bv in bgp.vlans)
                for vlan in bgp_vlans_to_remove:
                    LOG.debug("Removing stale bgp vlan %s from %s (%s) on config replace", vlan, self.name, self.host)
                    delete_req = EOSGNMIPaths.EVPN_INSTANCE.format(vlan=vlan)
                    config_req.delete.append(delete_req)

            for bgp_vlan in bgp.vlans:
                inst = {
                    "name": str(bgp_vlan.vlan),
                    "config": {
                        "name": str(bgp_vlan.vlan),
                        "redistribute": ["LEARNED", "ROUTER_MAC", "HOST_ROUTE"],
                    },
                    "vlans": {
                        "vlan": [{"vlan-id": bgp_vlan.vlan, "config": {"vlan-id": bgp_vlan.vlan}}],
                    }
                }

                cli = [
                    ("cli:", f"router bgp {bgp.asn}"),
                    ("cli:", f"vlan {bgp_vlan.vlan}"),
                ]

                # rd
                inst['config']['route-distinguisher'] = bgp_vlan.rd
                if bgp_vlan.rd_evpn_domain_all:
                    # FIXME: this should be done via model, once we have it
                    cli.append(("cli:", f"rd evpn domain all {bgp_vlan.rd}"))

                # route-targets
                if bgp_vlan.rt_imports or bgp_vlan.rt_exports:
                    rts = {}
                    if bgp_vlan.rt_imports:
                        rts["import"] = list(bgp_vlan.rt_imports)
                    if bgp_vlan.rt_exports:
                        rts["export"] = list(bgp_vlan.rt_exports)
                    inst["route-target"] = {"config": rts}

                # clean old route targets in bgw mode
                if operation == Op.replace:
                    for curr_vlan in bgp_vlans_on_switch:
                        if curr_vlan.vlan != bgp_vlan.vlan:
                            continue
                        if curr_vlan.rt_imports_evpn:
                            for rt in set(curr_vlan.rt_imports_evpn) - set(bgp_vlan.rt_imports_evpn or []):
                                cli.append(("cli:", f"no route-target import evpn domain remote {rt}"))
                        if curr_vlan.rt_exports_evpn:
                            for rt in set(curr_vlan.rt_exports_evpn) - set(bgp_vlan.rt_exports_evpn or []):
                                cli.append(("cli:", f"no route-target export evpn domain remote {rt}"))
                        break

                # FIXME: this should be done via model, once we have it
                for rt in bgp_vlan.rt_imports_evpn:
                    cli.append(("cli:", f"route-target import evpn domain remote {rt}"))
                for rt in bgp_vlan.rt_exports_evpn:
                    cli.append(("cli:", f"route-target export evpn domain remote {rt}"))
                cli.extend([("cli:", "exit"), ("cli:", "exit")])

                if bgp_vlan.rd_evpn_domain_all or bgp_vlan.rt_imports_evpn or bgp_vlan.rt_exports_evpn:
                    # even when we do a replace via GNMI it won't touch the evpn route targets
                    config_req.update_cli.extend(cli)

                # NOTE: We could do a replace every time, but replace takes ~320ms per whole call (not per
                #       evpn instance) vs ~32ms on update. This is only the case on a replace, where we have
                #       ROUTER_MAC, HOST_ROUTE as part of the "redistribute" key.
                config_req.get_list(operation).append((EOSGNMIPaths.EVPN_INSTANCE.format(vlan=bgp_vlan.vlan),
                                                       inst))
        else:
            for bgp_vlan in bgp.vlans:
                delete_req = EOSGNMIPaths.EVPN_INSTANCE.format(vlan=bgp_vlan.vlan)
                config_req.delete.append(delete_req)

    def get_iface_secondary_ips(self):
        ifaces = {}

        for entry in self.api.get(EOSGNMIPaths.IFACE_IPS_VIA_SYSDB, unpack=False)['notification']:
            # Sysdb/ip/config/ipIntfConfig/Vlan1337/virtualSecondaryWithMask
            if entry['prefix'].endswith("/virtualSecondaryWithMask"):
                ifname = entry['prefix'].split("/")[-2]
                ips = [u['path'] for u in entry['update']]
                ifaces[ifname] = ips

        return ifaces

    def get_iface_vrf_map(self):
        iface_vrf_map = {}
        for inst in self.api.get(EOSGNMIPaths.NETWORK_INSTANCES)['openconfig-network-instance:network-instance']:
            if 'interfaces' not in inst:
                continue
            for iface in inst['interfaces']['interface']:
                iface_vrf_map[iface['config']['interface']] = inst['name']
        return iface_vrf_map

    def get_ifaces_config(self, as_dict=False, with_vrfs=True):
        ifaces = []
        vlan_ifaces = []

        # get port-channel details
        pc_details = {}
        for pc in self.api.get("lacp")['openconfig-lacp:interfaces']['interface']:
            pc_details[pc['name']] = pc

        # secondary ips are only available via extra sysdb request
        all_secondary_ips = self.get_iface_secondary_ips()

        # vrfs are available in the network instances tree and need to be fetched seperately
        if with_vrfs:
            iface_vrf_map = self.get_iface_vrf_map()
        else:
            iface_vrf_map = {}

        # iterate over all ifaces on switch
        for data in self.api.get(EOSGNMIPaths.IFACES)['openconfig-interfaces:interface']:
            if data['config'].get('type') == 'iana-if-type:l3ipvlan':
                # l3 ifaces are a special case, as they are handled by a different config object
                vrf = iface_vrf_map.get(data['name'])
                vlan_iface = agent_msg.VlanIface(vlan=data['name'][len("vlan"):], vrf=vrf)

                # ip addresses
                ip_config = (data.get('arista-exp-eos-varp-intf:arista-varp', {})
                                 .get('virtual-address', {})
                                 .get('config'))
                if ip_config is not None:
                    vlan_iface.primary_ip = f"{ip_config['ip']}/{ip_config['prefix-length']}"

                if data['name'] in all_secondary_ips:
                    vlan_iface.secondary_ips = list(all_secondary_ips[data['name']])

                vlan_ifaces.append(vlan_iface)

                # no further processing
                continue

            iface = agent_msg.IfaceConfig(name=data['name'])

            # port-channel, normal iface or vlan iface?
            data_vlans = None
            if 'openconfig-if-aggregate:aggregation' in data:
                data_pc = data['openconfig-if-aggregate:aggregation']
                data_pc_cfg = data_pc.get('config', {})
                if not data_pc_cfg.get('arista-intf-augments:mlag') and not data['name'].startswith("Port-Channel"):
                    LOG.debug("Switch %s LACP iface %s has no mlag id and doesn't start with "
                              "'Port-Channel', skipping it",
                              self.name, data['name'])
                    continue
                iface.portchannel_id = data_pc_cfg.get('arista-intf-augments:mlag', data['name'][len("Port-Channel"):])
                if iface.portchannel_id:
                    iface.portchannel_id = int(iface.portchannel_id)
                if data['name'] in pc_details:
                    pc = pc_details[data['name']]
                    iface.members = [p['interface'] for p in pc.get('members', {}).get('member', [])]
                data_vlans = data_pc.get('openconfig-vlan:switched-vlan')
            elif 'openconfig-if-ethernet:ethernet' in data:
                data_if = data['openconfig-if-ethernet:ethernet']
                data_vlans = data_if.get('openconfig-vlan:switched-vlan')
            else:
                LOG.trace("Switch %s ignoring iface %s of type %s", self.name, data['name'], data['config'].get('type'))
                continue

            # vlans + translations
            if data_vlans and 'config' in data_vlans:
                # vlans
                if data_vlans['config'].get('native-vlan', 1) != 1:
                    iface.native_vlan = data_vlans['config']['native-vlan']
                if data_vlans['config'].get('trunk-vlans'):
                    vlans = []
                    for vlan in data_vlans['config']['trunk-vlans']:
                        if isinstance(vlan, str):
                            # range vlan: 2000..2004
                            vlan_from, vlan_to = map(int, vlan.split(".."))
                            vlans.extend(range(vlan_from, vlan_to + 1))
                        else:
                            vlans.append(vlan)
                    iface.trunk_vlans = vlans

                # vlan translations
                if 'vlan-translation:vlan-translation' in data_vlans:
                    ingress_maps = set()
                    for vtrans in data_vlans['vlan-translation:vlan-translation']['ingress']:
                        ingress_maps.add((vtrans['config']['translation-key'], vtrans['config']['bridging-vlan']))
                    egress_maps = set()
                    for vtrans in data_vlans['vlan-translation:vlan-translation']['egress']:
                        egress_maps.add((vtrans['config']['bridging-vlan'], vtrans['config']['translation-key']))

                    for inside, outside in ingress_maps & egress_maps:
                        iface.add_vlan_translation(inside=inside, outside=outside)

            ifaces.append(iface)

        ifaces.sort(key=attrgetter('name'))
        vlan_ifaces.sort(key=attrgetter('vlan'))

        if as_dict:
            iface_dict = {iface.name: iface for iface in ifaces}
            vlan_iface_dict = {viface.vlan: viface for viface in vlan_ifaces}
            return iface_dict, vlan_iface_dict

        return ifaces, vlan_ifaces

    def get_vlan_translations(self):
        """Get egress/ingress vlan translations from the device as a interface/bridging-vlan dict"""
        iface_map = {}
        for iface in self.api.get(EOSGNMIPaths.IFACES)['openconfig-interfaces:interface']:
            ifname = iface['name']
            if 'openconfig-if-aggregate:aggregation' in iface:
                iface = iface['openconfig-if-aggregate:aggregation']
            elif 'openconfig-if-ethernet:ethernet' in iface:
                iface = iface['openconfig-if-ethernet:ethernet']
            else:
                continue

            vtranslations = iface.get('openconfig-vlan:switched-vlan', {}).get('vlan-translation:vlan-translation')
            if not vtranslations:
                continue

            vtransdict = {'egress': {}, 'ingress': {}}
            for vtrans in vtranslations['ingress']:
                vtransdict['ingress'][vtrans['config']['bridging-vlan']] = vtrans['config']['translation-key']
            for vtrans in vtranslations['egress']:
                vtransdict['egress'][vtrans['config']['bridging-vlan']] = vtrans['config']['translation-key']
            iface_map[ifname] = vtransdict
        return iface_map

    def _make_ifaces_config(self, config_req: EOSSetConfig, ifaces: Optional[List[agent_msg.IfaceConfig]],
                            operation: Op):
        if operation in (Op.add, Op.replace):
            existing_vtrans = None  # only needed in add case and when vlan translations exist in config_req
            for iface in ifaces or []:
                # vlan stuff (native vlan, trunk vlans, translations)
                switched_vlan_config = {}
                vlan_config = {}

                # native vlan
                if iface.native_vlan:
                    vlan_config['native-vlan'] = iface.native_vlan

                # trunk vlans
                if iface.trunk_vlans:
                    vlan_config['interface-mode'] = 'TRUNK'
                    vlan_config['trunk-vlans'] = self._compress_vlan_list(iface.trunk_vlans)

                # vlan translations
                def remove_stale_vlan_translations(ifname, iface_cfg, is_pc):
                    # we need to delete an existing vlan mapping on "add" if the bridging-vlan is set
                    # on another vlan aka translation-key, else we'd get vlans mapped to multiple
                    # other vlans if something weird is already configured on the device
                    if existing_vtrans is None or ifname not in existing_vtrans:
                        return
                    for vtrans in iface_cfg.vlan_translations:
                        if existing_vtrans[ifname]['ingress'].get(vtrans.inside) not in (vtrans.outside, None):
                            vpath = (EOSGNMIPaths.IFACE_PC_VTRANS_INGRESS if is_pc
                                     else EOSGNMIPaths.IFACE_VTRANS_INGRESS)
                            tkey = existing_vtrans[ifname]['ingress'][vtrans.inside]
                            config_req.delete.append(vpath.format(iface=ifname, vlan=tkey))
                        if existing_vtrans[ifname]['egress'].get(vtrans.outside) not in (vtrans.inside, None):
                            vpath = (EOSGNMIPaths.IFACE_PC_VTRANS_EGRESS if is_pc
                                     else EOSGNMIPaths.IFACE_VTRANS_EGRESS)
                            tkey = existing_vtrans[ifname]['egress'][vtrans.outside]
                            config_req.delete.append(vpath.format(iface=ifname, vlan=tkey))

                if iface.vlan_translations:
                    if operation == Op.add and existing_vtrans is None:
                        existing_vtrans = self.get_vlan_translations()

                    vtrans_config = {}
                    vtrans_config['vlan-translation'] = {"ingress": [], "egress": []}
                    for vtrans in iface.vlan_translations:
                        vtrans_config['vlan-translation']['ingress'].append(
                            {"translation-key": vtrans.outside,
                             "config": {"translation-key": vtrans.outside, "bridging-vlan": vtrans.inside}})
                        vtrans_config['vlan-translation']['egress'].append(
                            {"translation-key": vtrans.inside,
                             "config": {"translation-key": vtrans.inside, "bridging-vlan": vtrans.outside}})
                    switched_vlan_config.update(vtrans_config)

                if vlan_config:
                    switched_vlan_config['config'] = vlan_config

                # port-channel configuration
                normal_ifaces = []
                if iface.portchannel_id is not None:
                    agg_data = {
                        'config': {
                            'mlag': iface.portchannel_id,
                            'lag-type': 'LACP',
                            'fallback': 'individual',
                            'fallback-timeout': 50,
                        },
                    }
                    if switched_vlan_config:
                        agg_data['switched-vlan'] = switched_vlan_config

                    data = {
                        'name': iface.name,
                        'config': {
                            'name': iface.name,
                            'type': 'iana-if-type:ieee8023adLag',
                        },
                        'aggregation': agg_data
                    }

                    if iface.vlan_translations:
                        remove_stale_vlan_translations(iface.name, iface, is_pc=True)

                    pc_cfg = (EOSGNMIPaths.IFACE.format(name=iface.name), data)
                    config_req.get_list(operation).append(pc_cfg)
                    normal_ifaces = iface.members or []
                else:
                    normal_ifaces = [iface.name]

                for iface_name in normal_ifaces:
                    data = {}
                    if iface.portchannel_id:
                        data['config'] = {'aggregate-id': f'Port-Channel{iface.portchannel_id}'}
                    if switched_vlan_config:
                        data['switched-vlan'] = switched_vlan_config
                    if iface.vlan_translations:
                        remove_stale_vlan_translations(iface_name, iface, is_pc=False)
                    if iface.speed:
                        if iface.speed in ('1g', '10g', '25g', '40g', '100g', '400g'):
                            eth_config = data.setdefault('config', {})
                            eth_config['port-speed'] = f"SPEED_{iface.speed.upper()}B"
                            eth_config['auto-negotiate'] = False
                            eth_config['duplex-mode'] = 'FULL'
                        else:
                            LOG.warning('Invalid interface speed "%s" for interface %s, ignoring it',
                                        iface.speed, iface.name)
                    iface_cfg = (EOSGNMIPaths.IFACE_ETH.format(iface=iface_name), data)
                    config_req.get_list(operation).append(iface_cfg)
        else:
            # delete everything (that is requested)
            def calc_delete_range(all_ifaces, iface_name, iface_cfg):
                if iface_name not in all_ifaces:
                    return []
                vlan_ints = list(set(all_ifaces[iface_name].trunk_vlans) - set(iface_cfg.trunk_vlans))
                return self._compress_vlan_list(vlan_ints)

            all_ifaces_cfg, _ = self.get_ifaces_config(as_dict=True, with_vrfs=False)
            for iface in ifaces or []:
                normal_ifaces = []
                if iface.portchannel_id is not None:
                    if iface.native_vlan:
                        config_req.delete.append(EOSGNMIPaths.IFACE_PC_NATIVE_VLAN.format(iface=iface.name))
                    if iface.trunk_vlans:
                        config_req.replace.append((EOSGNMIPaths.IFACE_PC_VTRUNKS.format(iface=iface.name),
                                                   calc_delete_range(all_ifaces_cfg, iface.name, iface)))

                    # NOTE: we only delete the translations based on one part of the translation
                    #       this means we could delete different translation. checking would require us
                    #       to do a replace on the existing translations by looking through the transaltion
                    #       dict in all_interfaces. If this happens we can change the implementation
                    for vtrans in iface.vlan_translations or []:
                        config_req.delete.append(EOSGNMIPaths.IFACE_PC_VTRANS_EGRESS
                                                 .format(iface=iface.name, vlan=vtrans.inside))
                        config_req.delete.append(EOSGNMIPaths.IFACE_PC_VTRANS_INGRESS
                                                 .format(iface=iface.name, vlan=vtrans.outside))
                    normal_ifaces = iface.members or []
                else:
                    normal_ifaces = [iface.name]

                for iface_name in normal_ifaces:
                    if iface.native_vlan:
                        config_req.delete.append(EOSGNMIPaths.IFACE_NATIVE_VLAN.format(iface=iface_name))

                    # delete trunk vlans
                    if iface.trunk_vlans:
                        config_req.replace.append((EOSGNMIPaths.IFACE_VTRUNKS.format(iface=iface_name),
                                                   calc_delete_range(all_ifaces_cfg, iface_name, iface)))
                    # delete translations
                    # NOTE: see note above for PC translations
                    for vtrans in iface.vlan_translations or []:
                        config_req.delete.append(EOSGNMIPaths.IFACE_VTRANS_EGRESS
                                                 .format(iface=iface_name, vlan=vtrans.inside))
                        config_req.delete.append(EOSGNMIPaths.IFACE_VTRANS_INGRESS
                                                 .format(iface=iface_name, vlan=vtrans.outside))

    def _make_vlan_ifaces_config(self, config_req: EOSSetConfig, vlan_ifaces: Optional[List[agent_msg.VlanIface]],
                                 operation: Op):
        if vlan_ifaces is None:
            return

        if operation in (Op.add, Op.replace):
            if operation == Op.replace:
                # clean up vlan interfaces we no longer need
                _, switch_vlan_ifaces = self.get_ifaces_config(with_vrfs=False)
                wanted_vlans = [vif.vlan for vif in vlan_ifaces]
                for switch_vif in switch_vlan_ifaces:
                    if switch_vif.vlan in self.managed_vlans and switch_vif.vlan not in wanted_vlans:
                        config_req.delete.append(EOSGNMIPaths.IFACE.format(name=f"Vlan{switch_vif.vlan}"))

            all_secondary_ips = self.get_iface_secondary_ips()
            for viface in vlan_ifaces:
                vifname = f"Vlan{viface.vlan}"
                vconfig = {"name": vifname, "config": {"name": vifname, "type": "l3ipvlan"}}

                # for the provided IPs we are always in replace mode
                # NOTE: having secondary IPs, but no primary IP will always remove all secondary IPs
                if viface.primary_ip:
                    vip, plen = viface.primary_ip.split("/", 2)
                    vconfig["arista-varp"] = {"virtual-address": {"config": {"ip": vip, "prefix-length": int(plen)}}}
                else:
                    # remove address from interface
                    config_req.delete.append(EOSGNMIPaths.IFACE_VIRTUAL_ADDRESS.format(name=vifname))

                # handle secondary ips
                secondary_ip_cmds = []
                if all_secondary_ips.get(vifname):
                    # clean unneeded secondary ips
                    for ip in all_secondary_ips[vifname]:
                        if ip not in (viface.secondary_ips or []):
                            secondary_ip_cmds.append(("cli:", f"no ip address virtual {ip} secondary"))

                for ip in viface.secondary_ips or []:
                    secondary_ip_cmds.append(("cli:", f"ip address virtual {ip} secondary"))

                if secondary_ip_cmds:
                    secondary_ip_cmds = [("cli:", f"interface {vifname}")] + secondary_ip_cmds + [("cli:", "exit")]
                    config_req.update_cli.extend(secondary_ip_cmds)

                config_req.update.append((EOSGNMIPaths.IFACE.format(name=vifname), vconfig))

                if viface.vrf:
                    config_req.update.append((EOSGNMIPaths.NETWORK_INSTANCE_IFACES.format(vrf=viface.vrf),
                                              {"interface": [{"id": vifname, "config": {"id": vifname}}]}))
        else:
            for viface in vlan_ifaces:
                config_req.delete.append(EOSGNMIPaths.IFACE.format(name=f"Vlan{viface.vlan}"))

    def _make_config_from_update(self, config: agent_msg.SwitchConfigUpdate) -> EOSSetConfig:
        # build config
        config_req = EOSSetConfig()
        self._make_vlan_config(config_req, config.vlans, config.operation)
        self._make_vxlan_mapping_config(config_req, config.vxlan_maps, config.operation)
        self._make_bgp_config(config_req, config.bgp, config.operation)
        self._make_ifaces_config(config_req, config.ifaces, config.operation)
        self._make_vlan_ifaces_config(config_req, config.vlan_ifaces, config.operation)

        return config_req

    def _get_config(self) -> agent_msg.SwitchConfigUpdate:
        # get infos from the device for everything that we have a model for
        config = agent_msg.SwitchConfigUpdate(switch_name=self.name, operation=Op.add)
        config.vlans = self.get_vlan_config()
        config.vxlan_maps = self.get_vxlan_mappings()
        config.bgp = self.get_bgp_config()
        config.ifaces, config.vlan_ifaces = self.get_ifaces_config()
        return config

    def _apply_config_update(self, config):
        # FIXME: threading model (does this call block or not?)
        #   option 1: synchronous applying the config
        #   option 2: put it into a queue, worker thread applies config
        # FIXME: blindly apply the config? or should we do an "inexpensive get" beforehand
        LOG.info("Device %s (%s) got new config: op %s vxlans %s interfaces %s",
                 self.name, self.host, config.operation.name, config.vxlan_maps, config.ifaces)

        config_req = self._make_config_from_update(config)
        try:
            if config_req.update_cli:
                # FIXME: this is not part of a transaction, it will not be reverted when the subsequent set() fails
                self.api.set(update=config_req.update_cli, encoding="ascii")
            self.api.set(delete=config_req.delete, replace=config_req.replace, update=config_req.update)
            self.metric_apply_config_update_success.labels(**self._def_labels).inc()
        except Exception as e:
            self.metric_apply_config_update_error.labels(exc_class=e.__class__.__name__, **self._def_labels).inc()
            LOG.error("Could not send config update to switch %s: %s %s",
                      self.name, e.__class__.__name__, e)
            raise

    def _persist_config(self):
        self.api.set(update=[("cli:", "copy running-config startup-config")], encoding="ascii")
