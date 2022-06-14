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

from collections import defaultdict
from operator import attrgetter
import re
import time

from oslo_log import log as logging
import pyeapi

from networking_ccloud.common.config import get_driver_config
from networking_ccloud.common import constants as cc_const
from networking_ccloud.common import exceptions as cc_exc
from networking_ccloud.ml2.agent.common import messages as agent_msg
from networking_ccloud.ml2.agent.common.messages import OperationEnum as Op
from networking_ccloud.ml2.agent.common.switch import SwitchBase

from typing import Dict, List, Optional

LOG = logging.getLogger(__name__)


class EOSSwitch(SwitchBase):

    CONFIGURE_ORDER = ['vlan', 'vxlan_mapping', 'bgp', 'ifaces']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.drv_conf = get_driver_config()

    @classmethod
    def get_platform(cls):
        return cc_const.PLATFORM_EOS

    def login(self):
        self._api = pyeapi.connect(
            transport="https", host=self.host, username=self.user, password=self._password,
            timeout=self.timeout)

    def send_cmd(self, cmd, fmt='json', raw=False, raise_on_error=True, _is_retry=False):
        """Send a command to the switch"""
        start_time = time.time()
        try:
            result = self.api.execute(cmd, format=fmt)
        except ConnectionError as e:
            if not _is_retry:
                return self.send_cmd(cmd, format=fmt, raw=raw, raise_on_error=raise_on_error, _is_retry=True)

            LOG.exception("Command failed in %.2fs on %s %s (even after retry), cmd: %s",
                          time.time() - start_time, self.name, self.host, cmd)
            raise cc_exc.SwitchConnectionError(f"{self.name} ({self.host}) {e}")
        except Exception as e:
            LOG.exception("Command failed in %.2fs on %s %s, cmd: %s",
                          time.time() - start_time, self.name, self.host, cmd)
            raise cc_exc.SwitchConnectionError(f"{self.name} ({self.host}) {e.__class__.__name__} {e}")

        LOG.debug("Command succeeded in %.2fs on %s %s, cmd: %s", time.time() - start_time, self.name, self.host, cmd)

        if not raw:
            # unpack the response a bit for easier handling
            # FIXME: will there always be a result? I think so, cause error cases are raised by pyeapi
            result = result['result']
            # unpack the response if user only specified a string as cmd
            if isinstance(cmd, str):
                result = result[0]

        return result

    def get_switch_status(self):
        ver = self.send_cmd("show version")

        return {
            'name': self.name,
            'host': self.host,
            'api_user': self.user,
            'version': ver['version'],
            'model': ver['modelName'],
            'uptime': ver['uptime'],
        }

    def get_vlan_config(self) -> List[agent_msg.Vlan]:
        vlans = [agent_msg.Vlan(vlan=int(vlan), name=data['name'])
                 for vlan, data in self.send_cmd("show vlan")['vlans'].items()]
        return sorted(vlans, key=attrgetter('vlan'))

    def _make_vlan_config(self, vlans: Optional[List[agent_msg.Vlan]], operation: Op) -> List[str]:
        commands = list()
        if vlans:
            if operation == Op.replace:
                wanted_vlans = [v.vlan for v in vlans]
                device_vlans = self.get_vlan_config()
                for device_vlan in map(attrgetter('vlan'), device_vlans):
                    # FIXME: either move this into constants or get this from config
                    # ignore default and peering vlans
                    if device_vlan <= 1 or device_vlan >= 4093:
                        continue
                    if device_vlan not in wanted_vlans:
                        commands.append(f"no vlan {device_vlan}")

            for vlan in vlans:
                if operation in (Op.add, Op.replace):
                    commands.append(f"vlan {vlan.vlan}")
                    if vlan.name:
                        name = vlan.name.replace(" ", "_")
                        commands.append(f"name {name}")
                    commands.append("exit")
                else:
                    commands.append(f"no vlan {vlan.vlan}")
        return commands

    def get_vxlan_mapping(self) -> List[agent_msg.VXLANMapping]:
        result = self.send_cmd("show interfaces Vxlan1")['interfaces']['Vxlan1']['vlanToVniMap']
        vxlan_maps = [agent_msg.VXLANMapping(vni=int(data['vni']), vlan=int(vlan))
                      for vlan, data in result.items() if 'vni' in data]
        return sorted(vxlan_maps, key=attrgetter('vlan'))

    def _make_vxlan_mapping_config(self, vxlan_maps: Optional[List[agent_msg.VXLANMapping]],
                                   operation: Op) -> List[str]:
        commands = list()
        if vxlan_maps is not None:
            commands.append("interface Vxlan1")

            # handle already existing mappings
            if operation in (Op.add, Op.replace):
                # purge mappings that are on the device but shouldn't
                curr_maps = self.get_vxlan_mapping()
                if operation == Op.add:
                    # purge mappings referenced by config update, but point to something else
                    for curr_map in curr_maps:
                        for os_map in vxlan_maps:
                            if (os_map.vlan == curr_map.vlan and os_map.vni != curr_map.vni) \
                                    or (os_map.vni == curr_map.vni and os_map.vlan != curr_map.vlan):
                                LOG.warning("Removing stale vxlan map <vni %s vlan %s> in favor of <vni %s vlan %s> "
                                            "on switch %s (%s)",
                                            curr_map.vni, curr_map.vlan, os_map.vni, os_map.vlan, self.name, self.host)
                                commands.append(f"no vxlan vlan {curr_map.vlan} vni {curr_map.vni}")
                else:
                    wanted_maps = [(v.vlan, v.vni) for v in vxlan_maps]
                    for curr_map in curr_maps:
                        if (curr_map.vlan, curr_map.vni) not in wanted_maps:
                            commands.append(f"no vxlan vlan {curr_map.vlan} vni {curr_map.vni}")

            # add / remove requested mappings
            for vmap in vxlan_maps:
                if operation in (Op.add, Op.replace):
                    commands.append(f"vxlan vlan add {vmap.vlan} vni {vmap.vni}")
                elif operation == Op.remove:
                    commands.append(f"no vxlan vlan {vmap.vlan} vni {vmap.vni}")
            commands.append("exit")
        return commands

    def get_bgp_vlan_config(self) -> List[agent_msg.BGPVlan]:
        curr_bgp_vlans = self.send_cmd("show bgp evpn instance")['bgpEvpnInstances']
        vre = re.compile(r"VLAN (?P<vlan>\d+)")
        bgp_vlans = list()
        for vlan_name, data in curr_bgp_vlans.items():
            m = vre.match(vlan_name)
            if not m:
                LOG.warning("Could not match bgp vpn instance name '%s'", vlan_name)
                continue

            bv = agent_msg.BGPVlan(rd=data['rd'], vlan=int(m.group('vlan')),
                                   rt_imports=data.get('importRts', []), rt_exports=data.get('exportRts', []),
                                   rd_evpn_domain_all='remoteRd' in data,
                                   rt_imports_evpn=data.get('importRemoteRts', []),
                                   rt_exports_evpn=data.get('exportRemoteRts', []))
            # FIXME: redistribute learned flag?
            bgp_vlans.append(bv)
        return bgp_vlans

    def get_bgp_config(self) -> agent_msg.BGP:
        bgp_sum = self.send_cmd("show bgp summary")['vrfs']['default']
        bgp = agent_msg.BGP(asn=bgp_sum['asn'], asn_region=self.drv_conf.global_config.asn_region, vlans=[])
        bgp.vlans = self.get_bgp_vlan_config()
        return bgp

    def _make_bgp_config(self, bgp: Optional[agent_msg.BGP], operation: Op) -> List[str]:
        commands = list()
        if bgp and bgp.vlans:
            commands.append(f"router bgp {bgp.asn}")

            # bgp vlan sections
            if bgp.vlans:
                if operation == Op.replace:
                    wanted_bgp_vlans = [bv.vlan for bv in bgp.vlans]
                    curr_bgp_vlans = self.get_bgp_vlan_config()
                    for entry in curr_bgp_vlans:
                        # FIXME: guard vlan range, same as above
                        if entry.vlan > 1 and entry.vlan < 4093 and entry.vlan not in wanted_bgp_vlans:
                            commands.append(f"no vlan {entry.vlan}")

                for bgp_vlan in bgp.vlans:
                    if operation in (Op.add, Op.replace):
                        commands.append(f"vlan {bgp_vlan.vlan}")

                        # rd
                        if bgp_vlan.rd_evpn_domain_all:
                            commands.append(f"rd evpn domain all {bgp_vlan.rd}")
                        else:
                            commands.append(f"rd {bgp_vlan.rd}")

                        # route-targets
                        for rt in bgp_vlan.rt_imports:
                            commands.append(f"route-target import {rt}")
                        for rt in bgp_vlan.rt_exports:
                            commands.append(f"route-target export {rt}")
                        for rt in bgp_vlan.rt_imports_evpn:
                            commands.append(f"route-target import evpn domain remote {rt}")
                        for rt in bgp_vlan.rt_exports_evpn:
                            commands.append(f"route-target export evpn domain remote {rt}")

                        commands.append("redistribute learned")
                        commands.append("exit")
                    else:
                        commands.append(f"no vlan {bgp_vlan.vlan}")

            commands.append("exit")
        return commands

    def get_vlan_translations(self, iface_name: Optional[str] = None) -> Dict[str, List[agent_msg.VlanTranslation]]:

        ifaces_vlan_maps = self.send_cmd(f"show interfaces {iface_name + ' ' if iface_name else ''}"
                                         "switchport vlan mapping")['intfVlanMappings']

        result = defaultdict(list)
        for name, data in ifaces_vlan_maps.items():
            # we're using ingressVlanMappings, but generally we expect them to be the
            # same as egressVlanMappings
            for o_vlan, data in data['ingressVlanMappings'].items():
                result[name].append(agent_msg.VlanTranslation(inside=data['vlanId'], outside=o_vlan))
        return result

    def get_ifaces_config(self) -> List[agent_msg.IfaceConfig]:

        iface_map = dict()

        def get_or_create_iface(name):
            if name not in iface_map:
                iface_map[name] = agent_msg.IfaceConfig(name=name)
            return iface_map[name]

        # vlans
        ifaces_vlans = self.send_cmd("show interfaces vlans")['interfaces']
        for name, data in ifaces_vlans.items():
            if name == "Vxlan1":
                continue
            iface = get_or_create_iface(name)
            if data.get("untaggedVlan", 1) != 1:
                iface.native_vlan = data['untaggedVlan']
            iface.trunk_vlans = data.get('taggedVlans', [])

        # vlan translations
        vtrans = self.get_vlan_translations()
        for name, translations in vtrans.items():
            iface = get_or_create_iface(name)
            # it comes from the device so we can assume its free of duplicates
            iface.vlan_translations = translations

        # portchannel info
        ifaces_pcs = self.send_cmd("show port-channel dense")['portChannels']
        for name, data in ifaces_pcs.items():
            if not name.startswith("Port-Channel"):
                continue
            iface = get_or_create_iface(name)
            iface.portchannel_id = int(name[len("Port-Channel"):])
            iface.members = [p for p in data["ports"] if not p.startswith("Peer")]

        return sorted(iface_map.values(), key=attrgetter('name'))

    def _make_ifaces_config(self, ifaces: Optional[List[agent_msg.IfaceConfig]], operation: Op) -> List[str]:
        commands = list()
        for iface in ifaces or []:
            generic_config = ["switchport mode trunk"]

            # native vlan
            if iface.native_vlan:
                if operation in (Op.add, Op.replace):
                    generic_config.append(f"switchport trunk native vlan {iface.native_vlan}")
                elif operation == Op.remove:
                    generic_config.append("no switchport trunk native vlan")

            # trunk vlans
            if iface.trunk_vlans:
                vlans = ",".join(map(str, iface.trunk_vlans))
                if operation == Op.add:
                    generic_config.append(f"switchport trunk allowed vlan add {vlans}")
                elif operation == Op.replace:
                    generic_config.append(f"switchport trunk allowed vlan {vlans}")
                elif operation == Op.remove:
                    generic_config.append(f"switchport trunk allowed vlan remove {vlans}")

            # vlan translations
            def get_removable_translations_cmds(iface_name, wanted_translations):
                vtrans = self.get_vlan_translations(iface_name=iface_name).popitem()[1]
                # interface name does not need to 100% match the interface we requested info for
                # (e24/1 vs Ethernet24/1) --> see what we got and use that
                # also we're using ingressVlanMappings, but generally we expect them to be the
                # same as egressVlanMappings
                remove_cmds = []
                for tra in vtrans:
                    if (tra.inside, tra.outside) not in wanted_translations:
                        remove_cmds.append(f"no switchport vlan translation {tra.outside} {tra.inside}")
                return remove_cmds

            if iface.vlan_translations:
                wanted_translations = [(v.inside, v.outside) for v in iface.vlan_translations]
                for vtr in iface.vlan_translations:
                    if operation in (Op.add, Op.replace):
                        generic_config.append(f"switchport vlan translation {vtr.outside} {vtr.inside}")
                    else:
                        generic_config.append(f"no switchport vlan translation {vtr.outside} {vtr.inside}")

            # lacp / member interface config
            if iface.portchannel_id is not None:
                commands.append(f"interface {iface.name}")
                if operation in (Op.add, Op.replace):
                    commands.append(f"mlag {iface.portchannel_id}")
                if iface.vlan_translations and operation == Op.replace:
                    commands += get_removable_translations_cmds(iface.name, wanted_translations)
                commands += generic_config
                commands.append("exit")
                normal_ifaces = iface.members or []
            else:
                normal_ifaces = [iface.name]

            for iface_name in normal_ifaces:
                commands.append(f"interface {iface_name}")
                if iface.portchannel_id is not None and operation in (Op.add, Op.replace):
                    commands.append(f"channel-group {iface.portchannel_id} mode active")
                if iface.vlan_translations and operation == Op.replace:
                    commands += get_removable_translations_cmds(iface_name, wanted_translations)
                commands += generic_config
                commands.append("exit")
        commands.append('end')

        return commands

    def _make_config_from_update(self, config: agent_msg.SwitchConfigUpdate) -> List[str]:
        # build config
        configmap = dict()

        configmap['vlan'] = self._make_vlan_config(config.vlans, config.operation)
        configmap['vxlan_mapping'] = self._make_vxlan_mapping_config(config.vxlan_maps, config.operation)
        configmap['bgp'] = self._make_bgp_config(config.bgp, config.operation)
        configmap['ifaces'] = self._make_ifaces_config(config.ifaces, config.operation)

        commands = ['configure']
        for k in self.CONFIGURE_ORDER:
            commands.extend(configmap[k])

        return commands

    def get_config(self) -> agent_msg.SwitchConfigUpdate:
        # get infos from the device for everything that we have a model for
        config = agent_msg.SwitchConfigUpdate(switch_name=self.name, operation=Op.add)
        config.vlans = self.get_vlan_config()
        config.vxlan_maps = self.get_vxlan_mapping()
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

        commands = self._make_config_from_update(config)
        try:
            self.send_cmd(commands)
        except Exception as e:
            LOG.error("Could not send config update to switch %s: %s %s",
                      self.name, e.__class__.__name__, e)
            raise
