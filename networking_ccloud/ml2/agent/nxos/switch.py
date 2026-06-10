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
import re

from oslo_log import log as logging
from typing import List, Optional, Tuple

from networking_ccloud.common import constants as cc_const
from networking_ccloud.ml2.agent.common.gnmi import CCGNMIClient
from networking_ccloud.ml2.agent.common import messages as agent_msg
from networking_ccloud.ml2.agent.common.messages import OperationEnum as Op
from networking_ccloud.ml2.agent.common.switch import SwitchBase

LOG = logging.getLogger(__name__)

# NXOS GNMI limitations
# https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/93x/progammability/guide/b-cisco-nexus-9000-series-nx-os-programmability-guide-93x/b-cisco-nexus-9000-series-nx-os-programmability-guide-93x_chapter_0110001.html
# https://github.com/openconfig/reference/blob/1cf43d2146f9ba70abb7f04f6b0f6eaa504cef05/rpc/gnmi/gnmi-specification.md


def guess_asn_format(asn):
    def _num_bytes(n):
        return 4 if n >> 16 else 2
    asval, nnval = asn.split(":", 1)
    return f"as{_num_bytes(int(asval))}-nn{_num_bytes(int(nnval))}"


class NXOSGNMIPaths:
    IFACE_VTRANS_ITEM = ("System/intf-items/phys-items/PhysIf-list[id={iface}]/vlanmapping-items/"
                         "vlantranslatetable-items/vlan-items/VlanTranslateEntry-list[vlanid=vlan-{inside}]"
                         "[translatevlanid=vlan-{outside}]")
    IFACE_PC_VTRANS_ITEM = ("System/intf-items/aggr-items/AggrIf-list[id={iface}]/vlanmapping-items/"
                            "vlantranslatetable-items/vlan-items/VlanTranslateEntry-list[vlanid=vlan-{inside}]"
                            "[translatevlanid=vlan-{outside}]")


class NXOSSetConfig:
    def __init__(self):
        self.delete = []
        self.replace = []
        self.update = []

    def get_list(self, op):
        if op == Op.add:
            return self.update
        elif op == Op.replace:
            return self.replace
        else:
            raise ValueError("Only available for add/replace")


class NXOSSwitch(SwitchBase):
    # path is System/intf-items/phys-items/PhysIf-list[id=eth1/17]/trunkVlans
    #         System/intf-items/aggr-items/AggrIf-list[id=po6]/trunkVlans
    IFDN_RE = re.compile(r"^System/intf-items/(?:aggr-items/AggrIf|phys-items/PhysIf)-list\[id=(?P<ifname>[^\]]+)]")
    # /System/inst-items/Inst-list[name='CC-CLOUD01']
    VRF_TDN_RE = re.compile(r"^/System/inst-items/Inst-list\[name='(?P<vrf>[^']+)'\]$")
    # System/bgp-items/inst-items/dom-items/Dom-list[name=CC-CLOUD01]...
    BGP_VRF_RE = re.compile(r"^System/bgp-items/inst-items/dom-items/Dom-list\[name=(?P<vrf>[^\]]+)\].*")
    # RM-CC-CLOUD01-D-AGGREGATE RM-CC-CLOUD01-AGGREGATE
    BGP_AGGREGATE_RM_RE = re.compile("^RM-(?P<vrf>[A-Z0-9-]+?)(?:-(?P<az>[A-Z]))?-AGGREGATE$")
    # PL-CC-CLOUD02 | PL-CC-CLOUD02-A | PL-CC-CLOUD02-EXTERNAL | PL-CC-CLOUD02-A-EXTERNAL
    PREFIX_LIST_RE = re.compile("PL-(?P<vrf>.*?)(?:-(?P<az>[A-Z]))?(?:-(?P<external>EXTERNAL))?$")
    # System/bd-items/bd-items/BD-list[fabEncap=vlan-3064]...
    BD_VLAN_RE = re.compile(r"System/bd-items/bd-items/BD-list\[fabEncap=vlan-(?P<vlan>\d+)\].*")

    # TODO(seba): remove this or convert to option - for now we still need to evaluate it
    OPT_GNMI_RUN_SEPARATE = False
    GNMI_CHUNK_SIZE = 20  # NXOS supports a maximum of 20 paths per request
    TRUNCATE_VLAN_NAMES = False

    @classmethod
    def get_platform(cls):
        return cc_const.PLATFORM_NXOS

    def login(self):
        self._api = CCGNMIClient(switch_name=self.name, host=self.host, port=50051,
                                 username=self.user, password=self._password, platform=self.get_platform(),
                                 insecure=False, skip_verify=True)
        self._api.connect()

    def _get_switch_status(self):
        fw_ver, model, uptime = self.api.get(path=[
            "/System/showversion-items/nxosVersion",
            "/System/ch-items/model",
            "/System/showversion-items/kernelUptime"])
        return {
            'name': self.name,
            'host': self.host,
            'api_user': self.user,
            'version': fw_ver,
            'model': model,
            'uptime': uptime,  # FIXME: convert to seconds since start
        }

    def get_vlan_and_vxmap_config(self) -> Tuple[List[agent_msg.Vlan], List[agent_msg.VXLANMapping]]:
        swdata = self.api.get(path=["/System/bd-items/bd-items"])['BD-list']
        vlans = []
        vxmaps = []
        for v in swdata:
            if v['id'] not in self.managed_vlans:
                continue
            vlans.append(agent_msg.Vlan(vlan=v['id'], name=v['name']))
            if v.get("accEncap", "").startswith("vxlan-"):
                vni = int(v['accEncap'][len("vxlan-"):])
                vxmaps.append(agent_msg.VXLANMapping(vlan=v['id'], vni=vni))
        return vlans, vxmaps

    def get_all_managed_vlan_ids_on_switch(self):
        vlans_on_switch = self.api.get(path=["/System/bd-items/bd-items/BD-list/id"], single=False)
        return set(vlans_on_switch) & set(self.managed_vlans)

    def get_all_vlan_vni_maps_on_switch(self):
        switch_vxmaps = self.api.get(path=['System/bd-items/bd-items/BD-list/accEncap'], single=False, with_path=True)
        vxmaps = set()
        for path, vni in switch_vxmaps:
            if not (m := self.BD_VLAN_RE.match(path)):
                continue
            vlan = int(m.group('vlan'))

            if not vni.startswith("vxlan-"):
                continue
            vni = int(vni[len("vxlan-"):])

            vxmaps.add((vlan, vni))
        return vxmaps

    def get_all_nve1_vnis_on_switch(self):
        return self.api.get(path=["/System/eps-items/epId-items/Ep-list[epId=1]/nws-items/vni-items/Nw-list/vni"],
                            single=False)

    def _make_vlan_and_vxmap_config(self, config_req: NXOSSetConfig, vlans: Optional[List[agent_msg.Vlan]],
                                    vxlan_maps: Optional[List[agent_msg.VXLANMapping]], svi_vlans: List[int],
                                    operation: Op) -> None:
        # vlans and vxlan_maps need to be populated together on NXOS
        # (the base driver code should always take care of this)
        if not (vlans and vxlan_maps):
            return

        vlan_vxmaps = {vx.vlan: vx.vni for vx in vxlan_maps}
        if {v.vlan for v in vlans} ^ set(vlan_vxmaps):
            LOG.warning("Inconsistent config request: Vlan IDs %s configured alongside vlan <-> vxlan maps %s on %s",
                        [v.vlan for v in vlans], list(vlan_vxmaps), self)

        if operation in (Op.add, Op.replace):
            if operation == Op.replace:
                # remove vlans managed by us that are not part of our mappings
                # (this is done as an extra block as we want to delete the vlan even if there's no vni mapped to it)
                vlans_to_remove = self.get_all_managed_vlan_ids_on_switch() - {v.vlan for v in vlans}
                for vlan in sorted(vlans_to_remove):
                    LOG.debug("Removing stale vlan %s from %s on config replace", vlan, self)
                    config_req.delete.append(f"/System/bd-items/bd-items/BD-list[fabEncap=vlan-{vlan}]")

                # remove the vni off of all vlans where we either manage the vlan and the vni is wrong or
                # where we manage the vni but not the vlan (and the vlan is not already removed)
                vxmaps_on_switch = self.get_all_vlan_vni_maps_on_switch() - set(vlan_vxmaps.items())
                for vlan, vni in vxmaps_on_switch:
                    if vlan in vlans_to_remove or (vlan not in self.managed_vlans and not self.is_managed_vni(vni)):
                        continue
                    LOG.debug("Cleaning stale vni %s off of vlan %s, as the vni is managed by us and is not mapped "
                              "to the right vlan", vni, vlan)
                    config_req.delete.append(f"/System/bd-items/bd-items/BD-list[fabEncap=vlan-{vlan}]/accEncap")

                # clean nve1
                all_cfg_vnis = {vx.vni for vx in vxlan_maps}
                vnis_to_delete = {dev_vni for dev_vni in self.get_all_nve1_vnis_on_switch()
                                  if dev_vni not in all_cfg_vnis and self.is_managed_vni(dev_vni)}
                for del_vni in sorted(vnis_to_delete):
                    LOG.debug("Removing stale vni %s from nve1", del_vni)
                    config_req.delete.append("/System/eps-items/epId-items/Ep-list[epId=1]/"
                                             f"nws-items/vni-items/Nw-list[vni={del_vni}]")

            # vlan part
            all_vlans = []
            for v in vlans:
                # create the vlan
                vlan_name = v.name
                if self.TRUNCATE_VLAN_NAMES and len(v.name) == 36:
                    # NOTE: when we don't trunk the vlan name then "system vlan long-name" needs to be configured
                    #       in some cases we had some problems with vlan names longer han 32 chars due to gnmi
                    #       truncating it again, but this seems to be fixed in recent NXOS firmwares
                    vlan_name = v.name.replace("-", "")
                vlan = {
                    'fabEncap': f"vlan-{v.vlan}",
                    'name': vlan_name,
                }
                if v.vlan in vlan_vxmaps:
                    vni = vlan_vxmaps[v.vlan]
                    vlan['accEncap'] = f"vxlan-{vni}"
                all_vlans.append(vlan)
            config_req.update.append(("/System/bd-items/bd-items", {'BD-list': all_vlans}))

            # nve1 part
            nve_list = []
            for vx in vxlan_maps:
                nve_item = {
                    'vni': vx.vni,
                    'suppressARP': 'enabled' if vx.vlan in svi_vlans else 'off',
                    # 'IngRepl-items': {'proto': 'bgp'},
                    'IngRepl-items': '',
                    'multisiteIngRepl': 'enable' if vx.enable_multisite else 'disable',
                }
                nve_list.append(nve_item)
            config_req.update.append(("/System/eps-items/epId-items/Ep-list[epId=1]/nws-items/vni-items",
                                      {'Nw-list': nve_list}))
        else:
            for v in vlans:
                config_req.delete.append(f"/System/bd-items/bd-items/BD-list[fabEncap=vlan-{v.vlan}]")
            for vx in vxlan_maps:
                config_req.delete.append("/System/eps-items/epId-items/Ep-list[epId=1]/"
                                         f"nws-items/vni-items/Nw-list[vni={vx.vni}]")

    def get_bgp_vlan_config(self, vxlan_maps: List[agent_msg.VXLANMapping]) -> List[agent_msg.BGPVlan]:
        # NXOS does not have a concept of vlan --> vni mappings in the bgp section
        # with our current data format we need to "emulate" this by looking at the already present vlan -> vni mappings
        # sw.grpc_get(path=["/System/evpn-items/bdevi-items"])["BDEvi-list"]
        vxmaps = {vx.vni: vx.vlan for vx in vxlan_maps}

        bdevis = self.api.get(path=["/System/evpn-items/bdevi-items"])["BDEvi-list"]
        bgp_vlans = []
        for bdevi in bdevis:
            if 'rd' not in bdevi or not bdevi['encap'].startswith("vxlan-"):
                continue
            vni = int(bdevi['encap'][len("vxlan-"):])
            if vni not in vxmaps:
                # for now, ignore everything not mapped to a vlan
                continue
            vlan = vxmaps[vni]
            # sample rd: rd:as2-nn4:4117:10091 ... or with the current bug rd:as2-nn2:4117:10091
            rd = bdevi['rd'].split(":", 3)[2]

            rt_exports = []
            rt_imports = []
            for rt_export_import in bdevi.get('rttp-items', {}).get('RttP-list', []):
                for rt_data in rt_export_import['ent-items']['RttEntry-list']:
                    # sample rt: route-target:as2-nn2:4:10091
                    rt = rt_data['rtt'].split(":", 2)
                    if rt_export_import['type'] == "export":
                        rt_exports.append(rt[-1])
                    elif rt_export_import['type'] == "import":
                        rt_imports.append(rt[-1])
                    else:
                        LOG.warning("Unknown rt type %s found in API of switch %s for vni %s",
                                    rt_export_import['type'], self, vni)

            # FIXME: implement BGW feature - until then, this is all left at non-BGW defaults
            bgp_vlan = agent_msg.BGPVlan(rd=rd, vlan=vlan, rt_imports=rt_imports, rt_exports=rt_exports)
            bgp_vlans.append(bgp_vlan)
        return bgp_vlans

    def get_bgp_vrf_config(self) -> List[agent_msg.BGPVRF]:
        bgpvrfs = {}

        # aggregates
        device_aggrs = self.api.get(path=["/System/bgp-items/inst-items/dom-items/Dom-list/"
                                          "af-items/DomAf-list/aggaddr-items"],
                                    single=False, with_path=True)
        for path, value in device_aggrs:
            m = self.BGP_VRF_RE.match(path)
            if not m:
                LOG.debug("Could not parse VRF from %s, skipping this BGPVRF", path)
                continue

            vrf = m.group('vrf')
            if vrf not in bgpvrfs:
                bgpvrfs[vrf] = agent_msg.BGPVRF(name=vrf)

            for aggr in value['AggAddr-list']:
                m = self.BGP_AGGREGATE_RM_RE.match(aggr['attrMap'])
                if not m:
                    continue
                if m.group('vrf') != vrf:
                    LOG.warning("BGPVRF %s routemap %s seems to have different VRF", vrf, m.group('vrf'))

                bgpvrfs[vrf].add_aggregates([
                    agent_msg.BGPVRFAggregate(network=aggr['addr'], az_local=bool(m.group('az')))
                ])

        # prefix lists
        # NOTE: could be refactored to save about 200ms (~320ms vs 120ms)
        #       sw.grpc_get(path=["/System/rpm-items/pfxlistv4-items/RuleV4-list/ent-items"], unpack=False)
        for pfx in self.api.get(path=["/System/rpm-items/pfxlistv4-items"])['RuleV4-list']:
            m = self.PREFIX_LIST_RE.match(pfx['name'])
            if not m:
                continue

            vrf = m.group('vrf')
            if vrf not in bgpvrfs:
                bgpvrfs[vrf] = agent_msg.BGPVRF(name=vrf)

            for addr in pfx.get('ent-items', {}).get('Entry-list', []):
                ip_addr = str(ipaddress.ip_network(addr['pfx'], strict=False))
                bgpvrfs[vrf].add_networks([
                    agent_msg.BGPVRFNetwork(network=ip_addr, az_local=bool(m.group('az')),
                                            ext_announcable=bool(m.group('external')))
                ])

        return sorted(list(bgpvrfs.values()))

    def get_bgp_config(self, vxlan_maps: List[agent_msg.VXLANMapping]) -> agent_msg.BGP:
        bgp_asn = self.api.get(path=["/System/bgp-items/inst-items/asn"])
        bgp = agent_msg.BGP(asn=bgp_asn, asn_region=self.asn_region, vlans=self.get_bgp_vlan_config(vxlan_maps))
        bgp.vrfs = self.get_bgp_vrf_config()

        return bgp

    def _make_bgp_config(self, config_req: NXOSSetConfig, bgp: Optional[agent_msg.BGP],
                         vxlan_maps: Optional[List[agent_msg.VXLANMapping]], operation: Op) -> None:
        if not bgp:
            return

        if vxlan_maps and bgp.vlans:
            self._make_bgp_vlans_config(config_req, bgp, vxlan_maps, operation)

        if bgp.vrfs:
            self._make_bgp_vrf_config(config_req, bgp.vrfs, operation)

    def get_all_evpn_vnis_on_switch(self):
        all_vnis = self.api.get(path=['/System/evpn-items/bdevi-items/BDEvi-list/encap'], single=False)
        return [int(vni[len("vxlan-"):]) for vni in all_vnis if vni.startswith("vxlan-")]

    def _make_bgp_vlans_config(self, config_req: NXOSSetConfig, bgp: Optional[agent_msg.BGP],
                               vxlan_maps: List[agent_msg.VXLANMapping], operation: Op) -> None:
        vlan_vxmaps = {vx.vlan: vx.vni for vx in vxlan_maps}
        if operation in (Op.add, Op.replace):
            if operation == Op.replace:
                all_cfg_vnis = {vx.vni for vx in vxlan_maps}
                vnis_to_delete = {dev_vni for dev_vni in self.get_all_evpn_vnis_on_switch()
                                  if dev_vni not in all_cfg_vnis and self.is_managed_vni(dev_vni)}
                for del_vni in vnis_to_delete:
                    LOG.debug("Removing stale vni %s from evpn config block", del_vni)
                    config_req.delete.append(f"/System/evpn-items/bdevi-items/BDEvi-list[encap=vxlan-{del_vni}]")

            bdevis = []
            for bgp_vlan in bgp.vlans:
                if bgp_vlan.vlan not in vlan_vxmaps:
                    continue
                vni = vlan_vxmaps[bgp_vlan.vlan]

                req = {
                    'encap': f"vxlan-{vni}",
                    # we're going with "rd auto", which is rd:unknown:0:0
                    # if we ever switch it we need to use as2-nn2/nn4, though the API had a bug at some point so it
                    # only accepts as2-nn2, independent of the actual rd value, i.e:
                    # 'rd': f"rd:as2-nn2:{bgp_vlan.rd}",
                    'rd': 'rd:unknown:0:0',  # configure "rd auto"
                }

                rts = []
                for action in ('export', 'import'):
                    rt_data = getattr(bgp_vlan, f'rt_{action}s')
                    if not rt_data:
                        continue

                    rt_list = []
                    for rt in rt_data:
                        # FIXME: why do the oper value differ from the normal rd in config?
                        rt_list.append({'rtt': f"route-target:{guess_asn_format(rt)}:{rt}"})

                    rts_entry = {
                        'type': action,
                        'ent-items': {'RttEntry-list': rt_list},
                    }
                    rts.append(rts_entry)

                if rts:
                    req['rttp-items'] = {'RttP-list': rts}

                # for a direct replace
                config_req.replace.append((f"/System/evpn-items/bdevi-items/BDEvi-list[encap=vxlan-{vni}]", req))

                bdevis.append(req)
            # commented out as we're doing a replace
            # config_req.update.append(('/System/evpn-items/bdevi-items', {'BDEvi-list': bdevis}))
        else:
            for bgp_vlan in bgp.vlans:
                if bgp_vlan.vlan not in vlan_vxmaps:
                    continue
                vni = vlan_vxmaps[bgp_vlan.vlan]
                delete_req = f"/System/evpn-items/bdevi-items/BDEvi-list[encap=vxlan-{vni}]"
                config_req.delete.append(delete_req)

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

    def _make_bgp_vrf_config(self, config_req: NXOSSetConfig, bgp_vrfs: Optional[List[agent_msg.BGPVRF]],
                             operation: Op):
        if bgp_vrfs is None:
            return

        if operation in (Op.add, Op.replace):
            for bgp_vrf in bgp_vrfs:
                # FIXME: are we sure we can do a full replace for the aggregates?
                #        Ben says "let's try it!"
                # aggregates
                # System/bgp-items/inst-items/dom-items/Dom-list[name=CC-CLOUD01]/af-items/DomAf-list[type=ipv4-ucast]/aggaddr-items

                aggrs = [
                    {"addr": bva.network, "attrMap": self.gen_route_map_name(bgp_vrf.name, bva.az_local)}
                    for bva in bgp_vrf.aggregates or []
                ]
                item = (
                    f"/System/bgp-items/inst-items/dom-items/Dom-list[name={bgp_vrf.name}]/"
                    f"af-items/DomAf-list[type=ipv4-ucast]/aggaddr-items",
                    {'AggAddr-list': aggrs}
                )
                config_req.get_list(operation).append(item)

                pfx_lists = {}
                if operation == Op.replace:
                    # on replace make sure we also empty lists where we don't have any prefixes for
                    for az_local in True, False:
                        for ext_announcable in True, False:
                            pfx_name = self.gen_prefix_list_name(bgp_vrf.name, az_local, ext_announcable)
                            pfx_lists[pfx_name] = []

                for bvn in bgp_vrf.networks or []:
                    pfx_name = self.gen_prefix_list_name(bgp_vrf.name, bvn.az_local, bvn.ext_announcable)
                    ipn = ipaddress.ip_network(bvn.network, strict=False)
                    order = int(ipn.network_address) or 1

                    pfx_lists.setdefault(pfx_name, []).append(
                        {
                            "order": order,
                            "pfx": str(ipn),
                        }
                    )

                for pfx_list_name, entries in pfx_lists.items():
                    if entries:
                        entry = {"Entry-list": entries}
                    else:
                        entry = {}

                    config_req.get_list(operation).append((
                        f"/System/rpm-items/pfxlistv4-items/RuleV4-list[name={pfx_list_name}]/ent-items",
                        entry
                    ))

        else:
            for bgp_vrf in bgp_vrfs:
                # aggregates
                for bva in bgp_vrf.aggregates or []:
                    config_req.delete.append(
                        f"/System/bgp-items/inst-items/dom-items/Dom-list[name={bgp_vrf.name}]/"
                        f"af-items/DomAf-list[type=ipv4-ucast]/aggaddr-items/AggAddr-list[addr={bva.network}]"
                    )

                # prefix lists
                if bgp_vrf.networks:
                    # TODO(seba): properly implement prefix list cleaning if needed
                    #             cleaning up prefix lists requires us to fetch the list and then selectively
                    #             delete entries based on order (pfx is not a key and therefore we can't delete
                    #             based on the key). This code is currently only for infra networks, which are
                    #             not used with nxos. We implement this once it's needed or remove the code path
                    #             from the driver
                    LOG.warning("BGP VRF prefix list cleaning not implemented yet for VRF %s for %s networks, "
                                "will be cleaned on next full sync", bgp_vrf.name, len(bgp_vrf.networks))

    def get_ifaces_config(self):
        # fetch physical interfaces, fetch portchannels
        ifaces = []
        ifdata = self.api.get(path=["/System/intf-items/phys-items"])['PhysIf-list']
        pcdata = self.api.get(path=["/System/intf-items/aggr-items"])['AggrIf-list']
        for data in (ifdata + pcdata):
            if data.get('rtmbrIfs-items'):
                # this interface is part of a portchannel, skipping reporting its config
                continue

            iface = agent_msg.IfaceConfig(name=data['id'])
            if data.get('descr'):
                iface.description = data['descr']
            if data.get('nativeVlan'):
                iface.native_vlan = data['nativeVlan'][len("vlan-"):]
            if data.get('trunkVlans'):
                iface.trunk_vlans = self._explode_vlan_list(data['trunkVlans'])
            if vtrans := data.get('vlanmapping-items', {}).get('vlantranslatetable-items'):
                for vt in vtrans['vlan-items']['VlanTranslateEntry-list']:
                    vtin = int(vt['vlanid'][len("vlan-"):])
                    vtout = int(vt['translatevlanid'][len("vlan-"):])
                    iface.add_vlan_translation(vtin, vtout)

            if 'pcId' in data:
                iface.portchannel_id = data['pcId']
                iface.members = []
                for member in data.get('bndlmbrif-items', {}).get('BndlMbrIf-list', []):
                    iface.members.append(member['id'])

            ifaces.append(iface)

        return ifaces

    @staticmethod
    def _explode_vlan_list(vlan_str, range_delim='-', delim=','):
        # FIXME: eos agent could use this as well
        # 123-124,126 or 1-4094 or 2000
        vlans = []
        if not vlan_str:
            # empty string --> no vlans on port
            return vlans

        for elem in vlan_str.split(delim):
            if range_delim in elem:
                from_vlan, to_vlan = elem.split(range_delim)
                vlans.extend(range(int(from_vlan), int(to_vlan) + 1))
            else:
                vlans.append(int(elem))
        return vlans

    def get_iface_trunks_and_translations(self):
        # doing a global get on trunkVlans / vlanmapping-items is 600ms each (on a specific switch)
        # pulling all interface info takes 2000ms
        ifaces = {}
        data = self.api.get(path=["/System/intf-items/*/*/trunkVlans"], unpack=False)
        for trunks in data['notification'][0]['update']:
            if m := self.IFDN_RE.match(trunks['path']):
                ifdata = ifaces.setdefault(m.group('ifname'), {})
                ifdata['trunks'] = self._explode_vlan_list(trunks['val'])

        try:
            data = self.api.get(path=["/System/intf-items/*/*/vlanmapping-items"], unpack=False)
            vtrans_data = data['notification'][0]['update']
        except Exception as e:
            # FIXME: we should not catch exception but something relevant
            # FIXME: we should ALSO probably disable the retry here?
            LOG.warning("No translations found on switch, skipping, exception was %s %s", e, e.__class__.__name__)
            vtrans_data = []

        for vtrans in vtrans_data:
            if 'vlantranslatetable-items' not in vtrans['val']:
                continue
            if m := self.IFDN_RE.match(vtrans['path']):
                ifdata = ifaces.setdefault(m.group('ifname'), {})
                ifdata['vlan_translations'] = []
                for elem in vtrans['val']['vlantranslatetable-items']['vlan-items']['VlanTranslateEntry-list']:
                    inside = int(elem['vlanid'][len("vlan-"):])
                    outside = int(elem['translatevlanid'][len("vlan-"):])
                    ifdata['vlan_translations'].append((inside, outside))

        return ifaces

    def _make_ifaces_config(self, config_req: NXOSSetConfig, ifaces: Optional[List[agent_msg.IfaceConfig]],
                            operation: Op):
        if not ifaces:
            return

        iface_configs = []
        pc_configs = []
        vpc_configs = []
        if operation in (Op.add, Op.replace):
            device_vlans_vtrans = {}
            if operation == Op.replace:
                device_vlans_vtrans = self.get_iface_trunks_and_translations()

            for iface in ifaces:
                iface_config = {
                    'id': iface.name,
                    'layer': 'Layer2',
                    'mode': 'trunk',
                }
                if iface.description is not None:
                    iface_config['descr'] = iface.description

                if iface.native_vlan:
                    iface_config['nativeVlan'] = f"vlan-{iface.native_vlan}"

                if iface.trunk_vlans:
                    # --> need to move aristas self._compress_vlan_list() somewhere accessible
                    iface_config['trunkVlans'] = [f"+{','.join(map(str, iface.trunk_vlans))}"]
                    if operation == Op.replace and iface.name in device_vlans_vtrans and \
                            device_vlans_vtrans[iface.name].get('trunks'):
                        device_trunks = device_vlans_vtrans[iface.name]['trunks']
                        vlans_to_remove = (set(device_trunks) & self.managed_vlans) - set(iface.trunk_vlans)
                        if vlans_to_remove:
                            iface_config['trunkVlans'].append(f"-{','.join(map(str, vlans_to_remove))}")

                if iface.vlan_translations:
                    vt_entries = []
                    for vt in iface.vlan_translations:
                        if vt.inside == vt.outside:
                            LOG.debug("Skipping vlan %s to itself on %s, not advised under NXOS", vt.inside, self)
                            continue
                        vt_entries.append({'vlanid': f"vlan-{vt.inside}", 'translatevlanid': f"vlan-{vt.outside}"})
                    if vt_entries:
                        vt_config = {
                            'Enabled': True,
                            'vlantranslatetable-items': {'vlan-items': {'VlanTranslateEntry-list': vt_entries}},
                        }
                        iface_config['vlanmapping-items'] = vt_config

                    # extra cleaning step:
                    if operation == Op.replace and iface.name in device_vlans_vtrans and \
                            device_vlans_vtrans[iface.name].get('vlan_translations'):
                        device_vtrans = device_vlans_vtrans[iface.name]['vlan_translations']
                        wanted_vtrans = [(vt.inside, vt.outside) for vt in iface.vlan_translations]
                        vtrans_to_delete = set(device_vtrans) - set(wanted_vtrans)
                        for vt_in, vt_out in vtrans_to_delete:
                            if iface.portchannel_id:
                                vt_del_dn = NXOSGNMIPaths.IFACE_PC_VTRANS_ITEM
                            else:
                                vt_del_dn = NXOSGNMIPaths.IFACE_VTRANS_ITEM
                            vt_del_dn = vt_del_dn.format(iface=iface.name, inside=vt_in, outside=vt_out)
                            config_req.delete.append(vt_del_dn)

                if iface.portchannel_id:
                    # port channel
                    iface_config['pcId'] = iface.portchannel_id
                    iface_config['suspIndividual'] = 'enable'
                    iface_config['pcMode'] = 'active'

                    # configure base interfaces to l2
                    rsmbr_ifaces = []
                    for member_iface in iface.members or []:
                        rsmbr_ifaces.append({'tDn': f"/System/intf-items/phys-items/PhysIf-list[id='{member_iface}']"})
                        member_iface_config = {'id': member_iface, 'layer': 'Layer2', 'mode': 'trunk'}
                        iface_configs.append(member_iface_config)

                    if rsmbr_ifaces:
                        iface_config['rsmbrIfs-items'] = {'RsMbrIfs-list': rsmbr_ifaces}

                    vpc_config = {
                        "id": iface.portchannel_id,
                        "rsvpcConf-items": {"tDn": f"/System/intf-items/aggr-items/AggrIf-list[id='{iface.name}']"},
                    }
                    vpc_configs.append(vpc_config)
                    pc_configs.append(iface_config)
                else:
                    # physical interface
                    iface_configs.append(iface_config)
        else:
            iface_configs = []
            pc_configs = []
            for iface in ifaces:
                iface_config = {'id': iface.name}

                if iface.native_vlan:
                    iface_config['nativeVlan'] = ''

                if iface.trunk_vlans:
                    iface_config['trunkVlans'] = f"-{','.join(map(str, iface.trunk_vlans))}"

                if iface.vlan_translations:
                    for vt in iface.vlan_translations:
                        if iface.portchannel_id:
                            vt_del_dn = NXOSGNMIPaths.IFACE_PC_VTRANS_ITEM
                        else:
                            vt_del_dn = NXOSGNMIPaths.IFACE_VTRANS_ITEM
                        vt_del_dn = vt_del_dn.format(iface=iface.name, inside=vt.inside, outside=vt.outside)
                        config_req.delete.append(vt_del_dn)
                    iface_config['vlanmapping-items'] = {}

                if iface.portchannel_id:
                    pc_configs.append(iface_config)
                else:
                    iface_configs.append(iface_config)

        if iface_configs:
            config_req.update.append(("/System/intf-items/phys-items", {'PhysIf-list': iface_configs}))
        if pc_configs:
            config_req.update.append(("/System/intf-items/aggr-items", {'AggrIf-list': pc_configs}))
        if vpc_configs:
            config_req.update.append(("/System/vpc-items/inst-items/dom-items/if-items", {'If-list': vpc_configs}))

    def get_vlan_ifaces(self) -> List[agent_msg.VlanIface]:
        svi_data = self.api.get(path=["/System/intf-items/svi-items"])['If-list']
        svis = []
        for svi in svi_data:
            vlan_id = int(svi['vlanId'])
            if vlan_id not in self.managed_vlans:
                continue

            # parse vrf
            vrf_tdn = svi['rtvrfMbr-items']['tDn']
            m = self.VRF_TDN_RE.match(vrf_tdn)
            if not m:
                LOG.warning("SVI %s has no parsable vrf tDN, skipping it - tDN was %s", vlan_id, vrf_tdn)
                continue
            vrf = m.group("vrf")

            # ip addresses: "/System/ipv4-items/inst-items/dom-items/Dom-list[name=CC-CLOUD01]
            #                /if-items/If-list[id=vlan2057]"
            # FIXME: what if the interface does not exist there?
            ips = self.api.get(path=[f"/System/ipv4-items/inst-items/dom-items/Dom-list[name={vrf}]"
                                     f"/if-items/If-list[id={svi['id']}]/addr-items"])
            primary_ip = None
            secondary_ips = []
            for ip in ips["Addr-list"]:
                if ip['type'] == 'primary':
                    primary_ip = ip['addr']
                else:
                    secondary_ips.append(ip['addr'])

            vlan_iface = agent_msg.VlanIface(vlan=vlan_id, vrf=vrf, primary_ip=primary_ip, secondary_ips=secondary_ips)
            svis.append(vlan_iface)
        return svis

    def _make_vlan_ifaces_config(self, config_req: NXOSSetConfig, vlan_ifaces: Optional[List[agent_msg.VlanIface]],
                                 operation: Op):
        if not vlan_ifaces:
            return

        if operation in (Op.add, Op.replace):
            if operation == Op.replace:
                all_svi_ids = set(self.api.get(path=["/System/intf-items/svi-items/If-list/vlanId"], single=False))
                keep_svi_ids = {vif.vlan for vif in vlan_ifaces}
                svi_ids_to_delete = (all_svi_ids & set(self.managed_vlans)) - keep_svi_ids
                for svi_id in svi_ids_to_delete:
                    config_req.delete.append(f"/System/intf-items/svi-items/If-list[id=vlan{svi_id}]")

            for vif in vlan_ifaces:
                vif_id = f"vlan{vif.vlan}"
                config_req.replace.append((
                    f"/System/intf-items/svi-items/If-list[id={vif_id}]",
                    {
                        "id": vif_id,
                        "adminSt": "up",
                        "inbMgmt": "false",
                        "mtu": 9000,
                        "rtvrfMbr-items": {
                            "tDn": f"/System/inst-items/Inst-list[name='{vif.vrf}']"
                        },
                        "vlanId": vif.vlan,
                    }
                ))

                config_req.replace.append((
                    f"/System/ipv4-items/inst-items/dom-items/Dom-list[name={vif.vrf}]/"
                    f"if-items/If-list[id={vif_id}]",
                    {
                        "id": vif_id,
                        "addr-items": {
                            "Addr-list": [
                                {
                                    "addr": ip,
                                    "type": "primary" if ip == vif.primary_ip else "secondary",
                                }
                                for ip in [vif.primary_ip] + (vif.secondary_ips or [])
                            ],
                        },
                        "directedBroadcast": "disabled",
                        "forward": "disabled",
                        "urpf": "disabled"
                    }
                ))

                config_req.replace.append((
                    f"/System/icmpv4-items/inst-items/dom-items/Dom-list[name={vif.vrf}]/"
                    f"if-items/If-list[id={vif_id}]",
                    {"id": vif_id, "ctrl": "port-unreachable"}
                ))

                config_req.replace.append((
                    f"/System/hmm-items/fwdinst-items/if-items/FwdIf-list[id={vif_id}]",
                    {
                        'id': vif_id,
                        'adminSt': 'enabled',
                        'hybrid-items': {'advertiseGW': False, 'enable': False},
                        'mode': 'anycastGW',
                    }
                ))
        else:
            for vif in vlan_ifaces:
                config_req.delete.append(f"/System/intf-items/svi-items/If-list[id=vlan{vif.vlan}]")

    def _make_config_from_update(self, config: agent_msg.SwitchConfigUpdate) -> NXOSSetConfig:
        svi_vlans = []
        if config.vlan_ifaces:
            svi_vlans = [svi.vlan for svi in config.vlan_ifaces]

        # build config
        config_req = NXOSSetConfig()
        self._make_vlan_and_vxmap_config(config_req, config.vlans, config.vxlan_maps, svi_vlans, config.operation)
        self._make_bgp_config(config_req, config.bgp, config.vxlan_maps, config.operation)
        self._make_ifaces_config(config_req, config.ifaces, config.operation)
        self._make_vlan_ifaces_config(config_req, config.vlan_ifaces, config.operation)

        return config_req

    def _get_config(self) -> agent_msg.SwitchConfigUpdate:
        config = agent_msg.SwitchConfigUpdate(switch_name=self.name, operation=Op.add)
        config.vlans, config.vxlan_maps = self.get_vlan_and_vxmap_config()
        config.bgp = self.get_bgp_config(config.vxlan_maps)
        config.ifaces = self.get_ifaces_config()
        config.vlan_ifaces = self.get_vlan_ifaces()
        return config

    def _apply_config_update(self, config):
        # FIXME: config pooling might not be the best option for NXOS, we'll have to investigate
        LOG.info("Device %s (%s) got new config: op %s vxlans %s interfaces %s",
                 self.name, self.host, config.operation.name, config.vxlan_maps, config.ifaces)

        config_req = self._make_config_from_update(config)
        LOG.debug("Device %s (%s) config update generated (d:%s, r:%s, u:%s)",
                  self.name, self.host, len(config_req.delete), len(config_req.replace), len(config_req.update))
        try:
            config_count = len(config_req.delete) + len(config_req.replace) + len(config_req.update)
            if self.OPT_GNMI_RUN_SEPARATE:
                for op in "delete", "replace", "update":
                    upd = {"delete": [], "replace": [], "update": []}
                    for entry in getattr(config_req, op):
                        LOG.debug("Applying config op %s with %s", op, entry)
                        upd[op] = [entry]
                        self.api.set(**upd)
            elif config_count > self.GNMI_CHUNK_SIZE:
                for op in "delete", "replace", "update":
                    entry = getattr(config_req, op)
                    if not entry:
                        continue

                    # chunk the request
                    for n in range((len(entry) - 1) // self.GNMI_CHUNK_SIZE + 1):
                        part_entry = entry[n * self.GNMI_CHUNK_SIZE: (n + 1) * self.GNMI_CHUNK_SIZE]
                        upd = {op: part_entry}
                        self.api.set(**upd)
            else:
                LOG.debug("Applying config update %s",
                          {"delete": config_req.delete, "replace": config_req.replace, "update": config_req.update})
                self.api.set(delete=config_req.delete, replace=config_req.replace, update=config_req.update)
            self.metric_apply_config_update_success.labels(**self._def_labels).inc()
        except Exception as e:
            self.metric_apply_config_update_error.labels(exc_class=e.__class__.__name__, **self._def_labels).inc()
            LOG.error("Could not send config update to switch %s: %s %s",
                      self, e.__class__.__name__, e)
            raise

    def _persist_config(self):
        LOG.warning("Persisting configuration is not yet supported by the agent, as it is not available in GNMI. "
                    "We will either use netconf-yang here or handle this externally.")
