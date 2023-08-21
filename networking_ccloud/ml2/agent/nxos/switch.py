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
import re

from oslo_log import log as logging
from typing import List, Optional

from networking_ccloud.common import constants as cc_const
from networking_ccloud.ml2.agent.common.gnmi import CCGNMIClient
from networking_ccloud.ml2.agent.common import messages as agent_msg
from networking_ccloud.ml2.agent.common.messages import OperationEnum as Op
from networking_ccloud.ml2.agent.common.switch import SwitchBase

LOG = logging.getLogger(__name__)

# NXOS GNMI limitations
# https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/93x/progammability/guide/b-cisco-nexus-9000-series-nx-os-programmability-guide-93x/b-cisco-nexus-9000-series-nx-os-programmability-guide-93x_chapter_0110001.html
# https://github.com/openconfig/reference/blob/1cf43d2146f9ba70abb7f04f6b0f6eaa504cef05/rpc/gnmi/gnmi-specification.md


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

    @classmethod
    def get_platform(self):
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

    def get_vlan_and_vxmap_config(self) -> (List[agent_msg.Vlan], List[agent_msg.VXLANMapping]):
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

    def _make_vlan_and_vxmap_config(self, config_req: NXOSSetConfig, vlans: Optional[List[agent_msg.Vlan]],
                                    vxlan_maps: Optional[List[agent_msg.VXLANMapping]], operation: Op) -> None:
        if not (vlans and vxlan_maps):
            return

        vlan_vxmaps = {vx.vlan: vx.vni for vx in vxlan_maps}
        if set(v.vlan for v in vlans) ^ set(vlan_vxmaps):
            # FIXME: should we handle this differently?
            LOG.warning("Inconsistent config request: Vlan IDs %s configured alongside vlan <-> vxlan maps %s on %s",
                        [v.vlan for v in vlans], list(vlan_vxmaps), self)

        if operation in (Op.add, Op.replace):
            if operation == Op.replace:
                vlans_to_remove = self.get_all_managed_vlan_ids_on_switch() - set(v.vlan for v in vlans)
                for vlan in sorted(vlans_to_remove):
                    LOG.debug("Removing stale vlan %s from %s on config replace", vlan, self)
                    config_req.delete.append(f"/System/bd-items/bd-items/BD-list[fabEncap=vlan-{vlan}]")
                # FIXME: we need to implement this for nve1, but we need the range of "managed VNIs" for that

            # vlan part
            all_vlans = []
            for v in vlans:
                # create the vlan
                vlan = {
                    'fabEncap': f"vlan-{v.vlan}",
                    'name': v.name,
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
                    'suppressARP': 'enabled',
                    'IngRepl-items': {'proto': 'bgp'},
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
            rd = bdevis['rd'].split(":", 3)[2]

            rt_exports = []
            rt_imports = []
            for rt_export_import in bdevi.get('rttp-items', {}).get('RttP-list', []):
                for rt_data in rt_export_import['ent-items']['RttEntry-list']:
                    # sample rt: route-target:as2-nn2:4:10091
                    rt = rt_data['rtt'].split(":", 3)
                    if rt_export_import['type'] == "export":
                        rt_exports.append(rt)
                    elif rt_export_import['type'] == "import":
                        rt_imports.append(rt)
                    else:
                        LOG.warning("Unknown rt type %s found in API of switch %s for vni %s",
                                    rt_export_import['type'], self, vni)

            # FIXME: implement BGW feature - until then, this is all left at non-BGW defaults
            bgp_vlan = agent_msg.BGPVlan(rd=rd, vlan=vlan, rt_imports=rt_imports, rt_exports=rt_exports)
            bgp_vlans.append(bgp_vlan)
        return bgp_vlans

    def get_bgp_config(self, vxlan_maps: List[agent_msg.VXLANMapping]) -> agent_msg.BGP:
        bgp_asn = self.api.get(path=["/System/bgp-items/inst-items/asn"])
        bgp = agent_msg.BGP(asn=bgp_asn, asn_region=self.asn_region, vlans=self.get_bgp_vlan_config(vxlan_maps))
        # FIXME: vrfs not implemented yet
        bgp.vrfs = []

        return bgp

    def _make_bgp_config(self, config_req: NXOSSetConfig, bgp: Optional[agent_msg.BGP],
                         vxlan_maps: Optional[List[agent_msg.VXLANMapping]], operation: Op) -> None:
        if bgp and vxlan_maps:
            if bgp.vlans:
                self._make_bgp_vlans_config(config_req, bgp, vxlan_maps, operation)

    def _make_bgp_vlans_config(self, config_req: NXOSSetConfig, bgp: Optional[agent_msg.BGP],
                               vxlan_maps: List[agent_msg.VXLANMapping], operation: Op) -> None:
        vlan_vxmaps = {vx.vlan: vx.vni for vx in vxlan_maps}
        if operation in (Op.add, Op.replace):
            # FIXME: implement replace
            #        ...we can't implement a proper replace yet, as we don't know which vnis we manage
            # self.api.get(path=["/System/evpn-items/bdevi-items/BDEvi-list/encap"], single=False)
            bdevis = []
            for bgp_vlan in bgp.vlans:
                if bgp_vlan.vlan not in vlan_vxmaps:
                    continue
                vni = vlan_vxmaps[bgp_vlan.vlan]

                req = {
                    'encap': f"vxlan-{vni}",
                    # FIXME: why do the oper value differ from the normal rd in config?
                    # 'rd': f"rd:as2-nn4:{bgp_vlan.rd}",
                    'rd': f"rd:as2-nn2:{bgp_vlan.rd}",
                }

                rts = []
                for action in ('export', 'import'):
                    rt_data = getattr(bgp_vlan, f'rt_{action}s')
                    if not rt_data:
                        continue

                    rt_list = []
                    for rt in rt_data:
                        # FIXME: why do the oper value differ from the normal rd in config?
                        # rt_list.append({'rtt': f"route-target:as2-nn4:{rt}"})
                        rt_list.append({'rtt': f"route-target:as2-nn2:{rt}"})

                    rts_entry = {
                        'type': action,
                        'ent-items': {'RttEntry-list': rt_list},
                    }
                    rts.append(rts_entry)

                if rts:
                    req['rttp-items'] = {'RttP-list': rts}
                bdevis.append(req)
            config_req.update.append(('/System/evpn-items/bdevi-items', {'BDEvi-list': bdevis}))
        else:
            for bgp_vlan in bgp.vlans:
                if bgp_vlan.vlan not in vlan_vxmaps:
                    continue
                vni = vlan_vxmaps[bgp_vlan.vlan]
                delete_req = f"/System/evpn-items/bdevi-items/BDEvi-list[encap={vni}]"
                config_req.delete.append(delete_req)

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
            if data.get('vlanmapping-items'):
                vmaps = data['vlanmapping-items']
                vtrans = vmaps['vlantranslatetable-items']['vlan-items']['VlanTranslateEntry-list']
                for vt in vtrans:
                    vtin = int(vt['vlanid'][len("vlan-"):])
                    vtout = int(vt['translatevlanid'][len("vlan-"):])
                    iface.add_vlan_translation(vtin, vtout)

            if 'pcId' in data:
                iface.portchannel_id = data['pcId']
                iface.members = []
                for member in data.get('bndlmbrif-items', {}).get('BndlMbrIf-list'):
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

        data = self.api.get(path=["/System/intf-items/*/*/vlanmapping-items"], unpack=False)
        for vtrans in data['notification'][0]['update']:
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
            device_vlans_vtrans = None
            if operation == Op.replace:
                device_vlans_vtrans = self.get_iface_trunks_and_translations()

            for iface in ifaces:
                # FIXME: replace stale vlans / handle replace

                # clean vlans
                # clean vlan translations

                iface_config = {
                    'id': iface.name,
                    'layer': 'Layer2',
                    'mode': 'trunk',
                }
                if iface.description is not None:
                    iface_config['descr'] = iface.description

                if iface.native_vlan or operation == Op.replace:
                    iface_config['nativeVlan'] = f"vlan-{iface.native_vlan}" if iface.native_vlan else ''

                if iface.trunk_vlans:
                    # --> need to move aristas self._compress_vlan_list() somewhere accessible
                    iface_config['trunkVlans'] = [f"+{','.join(map(str, iface.trunk_vlans))}"]
                    if operation == Op.replace and iface.name in device_vlans_vtrans and \
                            device_vlans_vtrans[iface.name].get('trunks'):
                        device_trunks = device_vlans_vtrans[iface.name]['trunks']
                        vlans_to_remove = (set(device_trunks) & self.managed_vlans) - set(iface.trunk_vlans)
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
                    vt_config = {}
                    for vt in iface.vlan_translations:
                        if iface.portchannel_id:
                            vt_del_dn = NXOSGNMIPaths.IFACE_PC_VTRANS_ITEM
                        else:
                            vt_del_dn = NXOSGNMIPaths.IFACE_VTRANS_ITEM
                        vt_del_dn = vt_del_dn.format(iface=iface.name, inside=vt.inside, outside=vt.outside)
                        config_req.delete.append(vt_del_dn)
                    iface_config['vlanmapping-items'] = vt_config

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

    def _make_config_from_update(self, config: agent_msg.SwitchConfigUpdate) -> NXOSSetConfig:
        # build config
        config_req = NXOSSetConfig()
        self._make_vlan_and_vxmap_config(config_req, config.vlans, config.vxlan_maps, config.operation)
        self._make_bgp_config(config_req, config.bgp, config.vxlan_maps, config.operation)
        self._make_ifaces_config(config_req, config.ifaces, config.operation)
        # FIXME: vlan ifaces

        return config_req

    def _get_config(self) -> agent_msg.SwitchConfigUpdate:
        config = agent_msg.SwitchConfigUpdate(switch_name=self.name, operation=Op.add)
        config.vlans, config.vxlan_maps = self.get_vlan_and_vxmap_config()
        config.bgp = self.get_bgp_config()
        config.ifaces = self.get_ifaces_config()
        # FIXME: vlan ifaces
        return config

    def _apply_config_update(self, config):
        # FIXME: config pooling might not be the best option for NXOS, we'll have to investigate
        LOG.info("Device %s (%s) got new config: op %s vxlans %s interfaces %s",
                 self.name, self.host, config.operation.name, config.vxlan_maps, config.ifaces)

        config_req = self._make_config_from_update(config)
        try:
            LOG.info("Applying config update %s",
                     dict(delete=config_req.delete, replace=config_req.replace, update=config_req.update))
            self.api.set(delete=config_req.delete, replace=config_req.replace, update=config_req.update)
            self.metric_apply_config_update_success.labels(**self._def_labels).inc()
        except Exception as e:
            self.metric_apply_config_update_error.labels(exc_class=e.__class__.__name__, **self._def_labels).inc()
            LOG.error("Could not send config update to switch %s: %s %s",
                      self, e.__class__.__name__, e)
            raise

    def _persist_config(self):
        LOG.warning("Persisting configuration is not yet supported by the agent, as we have not figured out how "
                    "to call the respective endpoint via GNMI yet")
