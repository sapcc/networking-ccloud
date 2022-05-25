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
import time

from oslo_log import log as logging
import pyeapi

from networking_ccloud.common.config import get_driver_config
from networking_ccloud.common import constants as cc_const
from networking_ccloud.common import exceptions as cc_exc
from networking_ccloud.ml2.agent.common import messages as agent_msg
from networking_ccloud.ml2.agent.common.messages import OperationEnum as Op
from networking_ccloud.ml2.agent.common.switch import SwitchBase

LOG = logging.getLogger(__name__)


class EOSSwitch(SwitchBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.drv_conf = get_driver_config()

    @classmethod
    def get_platform(self):
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

    def _make_config_from_update(self, config):
        # build config
        commands = ['configure']

        if config.vlans:
            if config.operation == Op.replace:
                wanted_vlans = [v.vlan for v in config.vlans]
                device_vlans = self.send_cmd("show vlan")['vlans']
                for device_vlan in map(int, device_vlans.keys()):
                    # FIXME: either move this into constants or get this from config
                    # ignore default and peering vlans
                    if device_vlan <= 1 or device_vlan >= 4093:
                        continue
                    if device_vlan not in wanted_vlans:
                        commands.append(f"no vlan {device_vlan}")

            for vlan in config.vlans:
                if config.operation in (Op.add, Op.replace):
                    commands.append(f"vlan {vlan.vlan}")
                    if vlan.name:
                        name = vlan.name.replace(" ", "_")
                        commands.append(f"name {name}")
                    commands.append("exit")
                else:
                    commands.append(f"no vlan {vlan.vlan}")

        # vxlan mappings
        if config.vxlan_maps is not None:
            commands.append("interface Vxlan1")

            if config.operation == Op.replace:
                # purge mappings that are on the device but shouldn't
                wanted_maps = [(v.vlan, v.vni) for v in config.vxlan_maps]
                curr_maps = self.send_cmd("show interfaces Vxlan1")['interfaces']['Vxlan1']['vlanToVniMap']
                for vlan, data in curr_maps.items():
                    if data.get('vni') and (int(vlan), data['vni']) not in wanted_maps:
                        commands.append(f"no vxlan vlan {vlan} vni {data['vni']}")

            # add / remove requested mappings
            for vmap in config.vxlan_maps:
                if config.operation in (Op.add, Op.replace):
                    commands.append(f"vxlan vlan add {vmap.vlan} vni {vmap.vni}")
                elif config.operation == Op.remove:
                    commands.append(f"no vxlan vlan {vmap.vlan} vni {vmap.vni}")
            commands.append("exit")

        # bgp section
        if config.bgp and config.bgp.vlans:
            commands.append(f"router bgp {config.bgp.asn}")

            # bgp vlan sections
            if config.bgp.vlans:
                if config.operation == Op.replace:
                    wanted_bgp_vlans = [bv.vlan for bv in config.bgp.vlans]
                    vre = re.compile(r"VLAN (?P<vlan>\d+)")
                    curr_bgp_vlans = self.send_cmd("show bgp evpn instance")['bgpEvpnInstances']
                    for entry in curr_bgp_vlans.keys():
                        m = vre.match(entry)
                        if m:
                            v = int(m.group('vlan'))
                            # FIXME: guard vlan range, same as above
                            if v > 1 and v < 4093 and v not in wanted_bgp_vlans:
                                commands.append(f"no vlan {v}")

                for bgp_vlan in config.bgp.vlans:
                    if config.operation in (Op.add, Op.replace):
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

        # ifaces
        for iface in config.ifaces or []:
            generic_config = ["switchport mode trunk"]

            # native vlan
            if iface.native_vlan:
                if config.operation in (Op.add, Op.replace):
                    generic_config.append(f"switchport trunk native vlan {iface.native_vlan}")
                elif config.operation == Op.remove:
                    generic_config.append("no switchport trunk native vlan")

            # trunk vlans
            if iface.trunk_vlans:
                vlans = ",".join(map(str, iface.trunk_vlans))
                if config.operation == Op.add:
                    generic_config.append(f"switchport trunk allowed vlan add {vlans}")
                elif config.operation == Op.replace:
                    generic_config.append(f"switchport trunk allowed vlan {vlans}")
                elif config.operation == Op.remove:
                    generic_config.append(f"switchport trunk allowed vlan remove {vlans}")

            # vlan translations
            def get_removable_translations_cmds(iface_name, wanted_translations):
                vtrans = self.send_cmd(f"show interfaces {iface_name} switchport vlan mapping")['intfVlanMappings']
                # interface name does not need to 100% match the interface we requested info for
                # (e24/1 vs Ethernet24/1) --> see what we got and use that
                # also we're using ingressVlanMappings, but generally we expect them to be the
                # same as egressVlanMappings
                vtrans = vtrans[list(vtrans.keys())[0]]['ingressVlanMappings']
                remove_cmds = []
                for o_vlan, data in vtrans.items():
                    if (data['vlanId'], int(o_vlan)) not in wanted_translations:
                        remove_cmds.append(f"no switchport vlan translation {o_vlan} {data['vlanId']}")
                return remove_cmds

            if iface.vlan_translations:
                wanted_translations = [(v.inside, v.outside) for v in iface.vlan_translations]
                for vtr in iface.vlan_translations:
                    if config.operation in (Op.add, Op.replace):
                        generic_config.append(f"switchport vlan translation {vtr.outside} {vtr.inside}")
                    else:
                        generic_config.append(f"no switchport vlan translation {vtr.outside} {vtr.inside}")

            # lacp / member interface config
            if iface.portchannel_id is not None:
                commands.append(f"interface {iface.name}")
                if config.operation in (Op.add, Op.replace):
                    commands.append(f"mlag {iface.portchannel_id}")
                if iface.vlan_translations and config.operation == Op.replace:
                    commands += get_removable_translations_cmds(iface.name, wanted_translations)
                commands += generic_config
                commands.append("exit")
                normal_ifaces = iface.members or []
            else:
                normal_ifaces = [iface.name]

            for iface_name in normal_ifaces:
                commands.append(f"interface {iface_name}")
                if iface.portchannel_id is not None and config.operation in (Op.add, Op.replace):
                    commands.append(f"channel-group {iface.portchannel_id} mode active")
                if iface.vlan_translations and config.operation == Op.replace:
                    commands += get_removable_translations_cmds(iface_name, wanted_translations)
                commands += generic_config
                commands.append("exit")
        commands.append('end')

        return commands

    def get_config(self):
        # get infos from the device for everything that we have a model for
        config = agent_msg.SwitchConfigUpdate(switch_name=self.name, operation=Op.add)

        # vlans
        for vlan, data in self.send_cmd("show vlan")['vlans'].items():
            config.add_vlan(int(vlan), data['name'])

        # vxlan_maps
        vxlan_maps = self.send_cmd("show interfaces Vxlan1")['interfaces']['Vxlan1']['vlanToVniMap']
        for vlan, data in vxlan_maps.items():
            if 'vni' in data:
                config.add_vxlan_map(int(data['vni']), int(vlan))

        # bgp
        bgp_sum = self.send_cmd("show bgp summary")['vrfs']['default']
        config.bgp = agent_msg.BGP(asn=bgp_sum['asn'], asn_region=self.drv_conf.global_config.asn_region, vlans=[])
        curr_bgp_vlans = self.send_cmd("show bgp evpn instance")['bgpEvpnInstances']
        vre = re.compile(r"VLAN (?P<vlan>\d+)")
        for vlan_name, data in curr_bgp_vlans.items():
            m = vre.match(vlan_name)
            if not m:
                LOG.warning("Could not match bgp vpn instanec name '%s'", vlan_name)
                continue

            bv = agent_msg.BGPVlan(rd=data['rd'], vlan=int(m.group('vlan')),
                                   rt_imports=data.get('importRts', []), rt_exports=data.get('exportRts', []),
                                   rd_evpn_domain_all='remoteRd' in data,
                                   rt_imports_evpn=data.get('importRemoteRts', []),
                                   rt_exports_evpn=data.get('exportRemoteRts', []))

            config.bgp.vlans.append(bv)
            # FIXME: redistribute learned flag?

        # ifaces - vlans
        ifaces_vlans = self.send_cmd("show interfaces vlans")['interfaces']
        for name, data in ifaces_vlans.items():
            if name == "Vxlan1":
                continue
            iface = config.get_or_create_iface(name)
            if data.get("untaggedVlan", 1) != 1:
                iface.native_vlan = data['untaggedVlan']
            iface.trunk_vlans = data.get('taggedVlans', [])

        # ifaces - vlan translations
        ifaces_vlan_maps = self.send_cmd("show interfaces switchport vlan mapping")['intfVlanMappings']
        for name, data in ifaces_vlan_maps.items():
            iface = config.get_or_create_iface(name)

            # we're using ingressVlanMappings, but generally we expect them to be the
            # same as egressVlanMappings
            for o_vlan, data in data['ingressVlanMappings'].items():
                iface.add_vlan_translation(data['vlanId'], int(o_vlan))

        # ifaces - portchannel info
        ifaces_pcs = self.send_cmd("show port-channel dense")['portChannels']
        for name, data in ifaces_pcs.items():
            if not name.startswith("Port-Channel"):
                continue
            iface = config.get_or_create_iface(name)
            iface.portchannel_id = int(name[len("Port-Channel"):])
            iface.members = [p for p in data["ports"] if not p.startswith("Peer")]

        # FIXME: ALL THE SORTING
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
