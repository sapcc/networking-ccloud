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

import json
from operator import attrgetter
import time
from typing import List, Optional

from oslo_log import log as logging
from pygnmi.client import gNMIclient, gNMIException

from networking_ccloud.common.config import get_driver_config
from networking_ccloud.common import constants as cc_const
from networking_ccloud.common import exceptions as cc_exc
from networking_ccloud.ml2.agent.common import messages as agent_msg
from networking_ccloud.ml2.agent.common.messages import OperationEnum as Op
from networking_ccloud.ml2.agent.common.switch import SwitchBase


LOG = logging.getLogger(__name__)


class EOSGNMIClient:

    class PATHS:
        VLANS = "network-instances/network-instance[name=default]/vlans"
        VLAN = "network-instances/network-instance[name=default]/vlans/vlan[vlan-id={vlan}]"

        VXMAP = "interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis"
        VXMAP_VLAN = ("interfaces/interface[name=Vxlan1]/arista-exp-eos-vxlan:arista-vxlan/config/vlan-to-vnis"
                      "/vlan-to-vni[vlan={vlan}]")

        EVPN_INSTANCES = "arista/eos/arista-exp-eos-evpn:evpn/evpn-instances"
        EVPN_INSTANCE = "arista/eos/arista-exp-eos-evpn:evpn/evpn-instances/evpn-instance[name={vlan}]"
        PROTO_BGP = "network-instances/network-instance[name=default]/protocols/protocol[name=BGP]"

        IFACES = "interfaces"
        IFACE = "interfaces/interface[name={iface}]"
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

    def __init__(self, switch_name, *args, **kwargs):
        self._gnmi = gNMIclient(*args, **kwargs)
        self._switch_name = switch_name

    def __repr__(self):
        return f"<{self.__class__.__name__} to {self._switch_name}>"

    def connect(self, *args, **kwargs):
        try:
            self._gnmi.close()  # doesn't raise on already closed connection
        except AttributeError:
            # probably never connected (no channel present)
            pass
        # FIXME: currently this throws Except (not retriable)
        #   would possibly raise a ConnectionRefusedError
        #   ConnectionRefusedError: [Errno 111] Connection refused
        LOG.debug("Connecting to switch %s", self._switch_name)
        try:
            self._gnmi.connect(*args, **kwargs)
        except Exception as e:
            raise cc_exc.SwitchConnectionError(f"{self._switch_name} connect() {e.__class__.__name__} {e}")

    def _run_method(self, method, *args, retries=3, **kwargs):
        try:
            start_time = time.time()
            data = getattr(self._gnmi, method)(*args, **kwargs)
            LOG.debug("Command %s() succeeded in %.2fs", method, time.time() - start_time)
            return data
        except gNMIException as e:
            LOG.exception("Command %s() failed on %s in %.2fs (retries left: %s): %s %s",
                          method, self._switch_name, time.time() - start_time, retries, e.__class__.__name__, str(e))

            cmd = [f"{method}("]
            if args:
                cmd.append(", ".join(map(json.dumps, args)))
            if kwargs:
                if args:
                    cmd.append(", ")
                cmd.append(", ".join(f"{k}={json.dumps(v)}" for k, v in kwargs.items()))
            cmd.append(")")
            cmd = "".join(cmd)
            LOG.debug("Failed command on %s was %s", self._switch_name, cmd)

            if isinstance(e, AttributeError):
                # module 'grpc' has no attribute '_channel', sometimes a first-connect problem
                LOG.info("Reconnecting %s because of %s %s", self._switch_name, e.__class__.__name__, str(e))
                self.connect()
            if retries > 0:
                time.sleep(0.5)
                return self._run_method(method, *args, retries=retries - 1, **kwargs)
            raise cc_exc.SwitchConnectionError(f"{self._switch_name} {method}() {e.__class__.__name__} {e}")

    def get(self, prefix="", path=None, *args, unpack=True, single=True, **kwargs):
        data = self._run_method("get", prefix, path, *args, **kwargs)
        if data and unpack:
            data = data['notification']
            if path and len(path) > 1:
                data = [x['update'] for x in data]
            else:
                data = [data[0]['update']]

            def _unpack(entry):
                if single:
                    return entry[0]['val']
                else:
                    return [x['val'] for x in entry]

            data = [_unpack(e) for e in data]

            if not (path and len(path) > 1):
                data = data[0]

        return data

    def set(self, *args, retries=3, **kwargs):
        return self._run_method("set", *args, **kwargs)


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

    CONFIGURE_ORDER = ['vlan', 'vxlan_mapping', 'bgp', 'ifaces']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.drv_conf = get_driver_config()

    @classmethod
    def get_platform(cls):
        return cc_const.PLATFORM_EOS

    def login(self):
        self._api = EOSGNMIClient(f"{self.name} ({self.host})",
                                  target=(self.host, 6030), username=self.user, password=self._password,
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

    def get_switch_status(self):
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
        swdata = self.api.get(EOSGNMIClient.PATHS.VLANS)["openconfig-network-instance:vlan"]
        vlans = [agent_msg.Vlan(vlan=v['vlan-id'], name=v['config']['name'])
                 for v in swdata]
        vlans.sort()
        return vlans

    def _make_vlan_config(self, config_req: EOSSetConfig, vlans: Optional[List[agent_msg.Vlan]], operation: Op) -> None:
        if vlans is None:
            return

        if operation in (Op.add, Op.replace):
            wanted_vlans = []
            for vlan in vlans:
                vcfg = {'vlan-id': vlan.vlan, 'config': {'name': vlan.name, 'vlan-id': vlan.vlan}}
                wanted_vlans.append(vcfg)
            vlan_cfg = (EOSGNMIClient.PATHS.VLANS, {'vlan': wanted_vlans})
            config_req.get_list(operation).append(vlan_cfg)
        else:
            for vlan in vlans:
                vpath = EOSGNMIClient.PATHS.VLAN.format(vlan=vlan.vlan)
                config_req.delete.append(vpath)

    def get_vxlan_mappings(self) -> List[agent_msg.VXLANMapping]:
        swdata = self.api.get(EOSGNMIClient.PATHS.VXMAP)['arista-exp-eos-vxlan:vlan-to-vni']
        vxlan_maps = [agent_msg.VXLANMapping(vni=v['vni'], vlan=v['vlan']) for v in swdata]
        vxlan_maps.sort()
        return vxlan_maps

    def _make_vxlan_mapping_config(self, config_req: EOSSetConfig, vxlan_maps: Optional[List[agent_msg.VXLANMapping]],
                                   operation: Op) -> None:
        if vxlan_maps is None:
            return

        curr_maps = self.get_vxlan_mappings()
        if operation in (Op.add, Op.replace):
            if operation == Op.add:
                # delete all mappings for VNIs we want to repurpose, but are used by a different vlan
                for curr_map in curr_maps:
                    for os_map in vxlan_maps:
                        if os_map.vni == curr_map.vni and os_map.vlan != curr_map.vlan:
                            LOG.warning("Removing stale vxlan map <vlan %s vni %s> in favor of <vlan %s vni %s> "
                                        "on switch %s (%s)",
                                        curr_map.vlan, curr_map.vni, os_map.vlan, os_map.vni, self.name, self.host)
                            del_map = EOSGNMIClient.PATHS.VXMAP_VLAN.format(vlan=curr_map.vlan)
                            config_req.delete.append(del_map)

            for vmap in vxlan_maps:
                mapcfg = (EOSGNMIClient.PATHS.VXMAP, {'vlan-to-vni': [{'vlan': vmap.vlan, 'vni': vmap.vni}]})
                config_req.get_list(operation).append(mapcfg)
        else:
            # delete vlan mapping only if it has the right vni
            for curr_map in curr_maps:
                for os_map in vxlan_maps:
                    if curr_map.vlan == os_map.vlan:
                        if curr_map.vni == os_map.vni:
                            config_req.delete.append(EOSGNMIClient.PATHS.VXMAP_VLAN.format(vlan=curr_map.vlan))
                        else:
                            LOG.warning("Not deleting vlan %s from switch %s (%s), as it points to vni %s "
                                        "(delete requested vni %s)",
                                        curr_map.vlan, self.name, self.host, curr_map.vni, os_map.vni)
                        break
                else:
                    LOG.warning("VLAN %s not found on switch %s (%s), not deleting it",
                                curr_map.vlan, self.name, self.host)

    def get_bgp_vlan_config(self) -> List[agent_msg.BGPVlan]:
        # FIXME: get potential bgw info per device from sysdb (not properly implemented)
        bgp_vlans = []
        curr_bgp_vlans = self.api.get(EOSGNMIClient.PATHS.EVPN_INSTANCES)["arista-exp-eos-evpn:evpn-instance"]
        for entry in curr_bgp_vlans:
            if not entry['name'].isdecimal():
                LOG.warning("Could not match bgp vpn instance name '%s' to a vlan", entry['name'])
                continue

            # FIXME: what happens if rd is None?
            rtdata = entry.get('route-target', {'config': {}})['config']
            rd = entry['config'].get('route-distinguisher')  # FIXME: this is bad. need to distinguish
            if not rd:
                LOG.debug("BGP Vlan %s on switch %s has no rd, skipping it", entry['name'], self.name)
                continue
            bv = agent_msg.BGPVlan(rd=rd, vlan=int(entry['name']),
                                   rt_imports=rtdata.get('import', []), rt_exports=rtdata.get('export', []),
                                   # eos_native:Sysdb/routing/bgp/macvrf/config/vlan.2323
                                   rd_evpn_domain_all=False,  # FIXME: get from somewhere
                                   rt_imports_evpn=[],       # FIXME: get from somewhere
                                   rt_exports_evpn=[])       # FIXME: get from somewhere
            # FIXME: redistribute learned flag? does not fit in our internal data structure
            bgp_vlans.append(bv)
        return bgp_vlans

    def get_bgp_config(self) -> agent_msg.BGP:
        bgp_asn = self.api.get(f"{EOSGNMIClient.PATHS.PROTO_BGP}/bgp/global/config/as")
        bgp = agent_msg.BGP(asn=bgp_asn, asn_region=self.drv_conf.global_config.asn_region,
                            vlans=self.get_bgp_vlan_config())
        return bgp

    def _make_bgp_config(self, config_req: EOSSetConfig, bgp: Optional[agent_msg.BGP], operation: Op) -> None:
        if not (bgp and bgp.vlans):
            return

        if operation in (Op.add, Op.replace):
            evpn_instances = []
            for bgp_vlan in bgp.vlans:
                inst = {
                    "name": str(bgp_vlan.vlan),
                    "config": {
                        "name": str(bgp_vlan.vlan),
                        "redistribute": ["LEARNED"],
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
                if bgp_vlan.rd_evpn_domain_all:
                    # FIXME: this should be done via model, once we have it
                    cli.append(("cli:", f"rd evpn domain all {bgp_vlan.rd}"))
                else:
                    inst['config']['route-distinguisher'] = bgp_vlan.rd

                # route-targets
                if bgp_vlan.rt_imports or bgp_vlan.rt_exports:
                    rts = {}
                    if bgp_vlan.rt_imports:
                        rts["import"] = list(bgp_vlan.rt_imports)
                    if bgp_vlan.rt_exports:
                        rts["export"] = list(bgp_vlan.rt_exports)
                    inst["route-target"] = {"config": rts}

                # FIXME: this should be done via model, once we have it
                # FIXME: what do we do if different route targets exist? they need to go / be removed
                for rt in bgp_vlan.rt_imports_evpn:
                    cli.append(("cli:", f"route-target import evpn domain remote {rt}"))
                for rt in bgp_vlan.rt_exports_evpn:
                    cli.append(("cli:", f"route-target export evpn domain remote {rt}"))
                cli.extend([("cli:", "exit"), ("cli:", "exit")])

                if bgp_vlan.rd_evpn_domain_all or bgp_vlan.rt_imports_evpn or bgp_vlan.rt_exports_evpn:
                    # FIXME: I think I checked that this works with replace, but we should make sure
                    config_req.update_cli.extend(cli)
                evpn_instances.append(inst)
            config_req.get_list(operation).append((EOSGNMIClient.PATHS.EVPN_INSTANCES,
                                                   {"evpn-instance": evpn_instances}))
        else:
            for bgp_vlan in bgp.vlans:
                delete_req = EOSGNMIClient.PATHS.EVPN_INSTANCE.format(vlan=bgp_vlan.vlan)
                config_req.delete.append(delete_req)

    def get_ifaces_config(self, as_dict=False):
        ifaces = []

        # get port-channel details
        pc_details = {}
        for pc in self.api.get("lacp")['openconfig-lacp:interfaces']['interface']:
            pc_details[pc['name']] = pc

        # iterate over all ifaces on switch
        for data in self.api.get(EOSGNMIClient.PATHS.IFACES)['openconfig-interfaces:interface']:
            iface = agent_msg.IfaceConfig(name=data['name'])

            # port-channel or not?
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
                    iface.members = [p['interface'] for p in pc['members']['member']]
                data_vlans = data_pc.get('openconfig-vlan:switched-vlan')
            elif 'openconfig-if-ethernet:ethernet' in data:
                data_if = data['openconfig-if-ethernet:ethernet']
                data_vlans = data_if.get('openconfig-vlan:switched-vlan')
            else:
                LOG.debug("Switch %s ignoring iface %s of type %s", self.name, data['name'], data['config'].get('type'))
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
        if as_dict:
            iface_dict = {}
            for iface in ifaces:
                iface_dict[iface.name] = iface
            return iface_dict

        return sorted(ifaces, key=attrgetter('name'))

    def get_vlan_translations(self):
        """Get egress/ingress vlan translations from the device as a interface/bridging-vlan dict"""
        iface_map = {}
        for iface in self.api.get(EOSGNMIClient.PATHS.IFACES)['openconfig-interfaces:interface']:
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
                            operation: Op) -> List[str]:
        if operation in (Op.add, Op.replace):
            existing_vtrans = None  # only needed in add case and when vlan translations exist in config_req
            for iface in ifaces or []:
                # vlan stuff (native vlan, trunk vlans, translations)
                data_vlan = {}

                # native vlan
                if iface.native_vlan:
                    data_vlan['native-vlan'] = iface.native_vlan

                # trunk vlans
                if iface.trunk_vlans:
                    data_vlan['interface-mode'] = 'TRUNK'
                    data_vlan['trunk-vlans'] = self._compress_vlan_list(iface.trunk_vlans)

                # vlan translations
                def remove_stale_vlan_translations(ifname, iface_cfg, is_pc):
                    # we need to delete an existing vlan mapping on "add" if the bridging-vlan is set
                    # on another vlan aka translation-key, else we'd get vlans mapped to multiple
                    # other vlans if something weird is already configured on the device
                    if existing_vtrans is None or ifname not in existing_vtrans:
                        return
                    for vtrans in iface_cfg.vlan_translations:
                        if existing_vtrans[ifname]['ingress'].get(vtrans.inside) not in (vtrans.outside, None):
                            vpath = (EOSGNMIClient.PATHS.IFACE_PC_VTRANS_INGRESS if is_pc
                                     else EOSGNMIClient.PATHS.IFACE_VTRANS_INGRESS)
                            tkey = existing_vtrans[ifname]['ingress'][vtrans.inside]
                            config_req.delete.append(vpath.format(iface=ifname, vlan=tkey))
                        if existing_vtrans[ifname]['egress'].get(vtrans.outside) not in (vtrans.inside, None):
                            vpath = (EOSGNMIClient.PATHS.IFACE_PC_VTRANS_EGRESS if is_pc
                                     else EOSGNMIClient.PATHS.IFACE_VTRANS_EGRESS)
                            tkey = existing_vtrans[ifname]['egress'][vtrans.outside]
                            config_req.delete.append(vpath.format(iface=ifname, vlan=tkey))

                if iface.vlan_translations:
                    if operation == Op.add and existing_vtrans is None:
                        existing_vtrans = self.get_vlan_translations()

                    data_vlan['vlan-translation'] = {"ingress": [], "egress": []}
                    for vtrans in iface.vlan_translations:
                        data_vlan['vlan-translation']['ingress'].append(
                            {"translation-key": vtrans.outside,
                             "config": {"translation-key": vtrans.outside, "bridging-vlan": vtrans.inside}})
                        data_vlan['vlan-translation']['egress'].append(
                            {"translation-key": vtrans.inside,
                             "config": {"translation-key": vtrans.inside, "bridging-vlan": vtrans.outside}})

                # port-channel configuration
                normal_ifaces = []
                if iface.portchannel_id is not None:
                    data = {
                        'config': {
                            'arista-intf-augments:mlag': iface.portchannel_id,
                            'lag-type': 'LACP',
                            'arista-intf-augments:fallback': 'individual',
                        },
                    }
                    if data_vlan:
                        data['switched-vlan'] = {'config': data_vlan}

                    if iface.vlan_translations:
                        remove_stale_vlan_translations(iface.name, iface, is_pc=True)

                    pc_cfg = (EOSGNMIClient.PATHS.IFACE_PC.format(iface=iface.name), data)
                    config_req.get_list(operation).append(pc_cfg)
                    normal_ifaces = iface.members or []
                else:
                    normal_ifaces = [iface.name]

                for iface_name in normal_ifaces:
                    data = {}
                    if iface.portchannel_id:
                        data['config'] = {'aggregate-id': f'Port-Channel{iface.portchannel_id}'}
                    if data_vlan:
                        data['switched-vlan'] = {'config': data_vlan}
                    if iface.vlan_translations:
                        remove_stale_vlan_translations(iface_name, iface, is_pc=False)
                    iface_cfg = (EOSGNMIClient.PATHS.IFACE_ETH.format(iface=iface_name), data)
                    config_req.get_list(operation).append(iface_cfg)
        else:
            # delete everything (that is requested)
            def calc_delete_range(all_ifaces, iface_name, iface_cfg):
                if iface_name not in all_ifaces:
                    return []
                vlan_ints = list(set(all_ifaces[iface_name].trunk_vlans) - set(iface_cfg.trunk_vlans))
                return self._compress_vlan_list(vlan_ints)

            all_ifaces_cfg = self.get_ifaces_config(as_dict=True)
            for iface in ifaces or []:
                normal_ifaces = []
                if iface.portchannel_id is not None:
                    if iface.native_vlan:
                        config_req.delete.append(EOSGNMIClient.PATHS.IFACE_PC_NATIVE_VLAN.format(iface=iface.name))
                    if iface.trunk_vlans:
                        config_req.replace.append((EOSGNMIClient.PATHS.IFACE_PC_VTRUNKS.format(iface=iface.name),
                                                   calc_delete_range(all_ifaces_cfg, iface.name, iface)))

                    # NOTE: we only delete the translations based on one part of the translation
                    #       this means we could delete different translation. checking would require us
                    #       to do a replace on the existing translations by looking through the transaltion
                    #       dict in all_interfaces. If this happens we can change the implementation
                    for vtrans in iface.vlan_translations or []:
                        config_req.delete.append(EOSGNMIClient.PATHS.IFACE_PC_VTRANS_EGRESS
                                                 .format(iface=iface.name, vlan=vtrans.inside))
                        config_req.delete.append(EOSGNMIClient.PATHS.IFACE_PC_VTRANS_INGRESS
                                                 .format(iface=iface.name, vlan=vtrans.outside))
                    normal_ifaces = iface.members or []
                else:
                    normal_ifaces = [iface.name]

                for iface_name in normal_ifaces:
                    if iface.native_vlan:
                        config_req.delete.append(EOSGNMIClient.PATHS.IFACE_NATIVE_VLAN.format(iface=iface_name))

                    # delete trunk vlans
                    if iface.trunk_vlans:
                        config_req.replace.append((EOSGNMIClient.PATHS.IFACE_VTRUNKS.format(iface=iface_name),
                                                   calc_delete_range(all_ifaces_cfg, iface_name, iface)))
                    # delete translations
                    # NOTE: see note above for PC translations
                    for vtrans in iface.vlan_translations or []:
                        config_req.delete.append(EOSGNMIClient.PATHS.IFACE_VTRANS_EGRESS
                                                 .format(iface=iface_name, vlan=vtrans.inside))
                        config_req.delete.append(EOSGNMIClient.PATHS.IFACE_VTRANS_INGRESS
                                                 .format(iface=iface_name, vlan=vtrans.outside))

    def _make_config_from_update(self, config: agent_msg.SwitchConfigUpdate) -> EOSSetConfig:
        # build config
        config_req = EOSSetConfig()
        self._make_vlan_config(config_req, config.vlans, config.operation)
        self._make_vxlan_mapping_config(config_req, config.vxlan_maps, config.operation)
        self._make_bgp_config(config_req, config.bgp, config.operation)
        self._make_ifaces_config(config_req, config.ifaces, config.operation)

        return config_req

    def get_config(self) -> agent_msg.SwitchConfigUpdate:
        # get infos from the device for everything that we have a model for
        config = agent_msg.SwitchConfigUpdate(switch_name=self.name, operation=Op.add)
        config.vlans = self.get_vlan_config()
        config.vxlan_maps = self.get_vxlan_mappings()
        config.bgp = self.get_bgp_config()
        config.ifaces = self.get_ifaces_config()
        return config

    def apply_config_update(self, config):
        # FIXME: threading model (does this call block or not?)
        #   option 1: synchronous applying the config
        #   option 2: put it into a queue, worker thread applies config
        # FIXME: blindly apply the config? or should we do an "inexpensive get" beforehand
        LOG.info("Device %s %s got new config: vxlans %s interfaces %s",
                 self.name, self.host, config.vxlan_maps, config.ifaces)

        config_req = self._make_config_from_update(config)
        try:
            if config_req.update_cli:
                # FIXME: this is not part of a transaction, it will not be reverted when the subsequent set() fails
                self.api.set(update=config_req.update_cli, encoding="ascii")
            self.api.set(delete=config_req.delete, replace=config_req.replace, update=config_req.update)
        except Exception as e:
            LOG.error("Could not send config update to switch %s: %s %s",
                      self.name, e.__class__.__name__, e)
            raise
