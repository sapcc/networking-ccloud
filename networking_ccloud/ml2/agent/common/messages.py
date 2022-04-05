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

from enum import Enum
from typing import List

from oslo_log import log as logging
import pydantic

from networking_ccloud.common.config.config_driver import validate_asn
from networking_ccloud.ml2.agent.common.api import CCFabricSwitchAgentRPCClient

LOG = logging.getLogger(__name__)


class OperationEnum(str, Enum):
    add = 'add'
    remove = 'remove'
    replace = 'replace'


class Vlan(pydantic.BaseModel):
    vlan: pydantic.conint(gt=0, lt=4094)
    name: str = None


class VXLANMapping(pydantic.BaseModel):
    vni: pydantic.conint(gt=0, lt=2**24)
    vlan: pydantic.conint(gt=0, lt=4094)


class BGPVlan(pydantic.BaseModel):
    # FIXME: validator
    rd: str
    vlan: pydantic.conint(gt=0, lt=4094)
    vni: pydantic.conint(gt=0, lt=2**24)
    bgw_mode: bool = False


class BGP(pydantic.BaseModel):
    asn: str

    # regional asn (only used for bgws)
    asn_region: str

    vlans: List[BGPVlan] = None

    _normalize_asn = pydantic.validator('asn', allow_reuse=True)(validate_asn)
    _normalize_asn_region = pydantic.validator('asn_region', allow_reuse=True)(validate_asn)

    def add_vlan(self, rd, vlan, vni, bgw_mode=False):
        if not self.vlans:
            self.vlans = []
        for bv in self.vlans:
            if bv.rd == rd and bv.vlan == vlan and bv.vni == vni:
                return
        self.vlans.append(BGPVlan(rd=rd, vlan=vlan, vni=vni, bgw_mode=bgw_mode))


class VlanTranslation(pydantic.BaseModel):
    inside: pydantic.conint(gt=0, lt=4094)
    outside: pydantic.conint(gt=0, lt=4094)


class IfaceConfig(pydantic.BaseModel):
    name: str

    native_vlan: pydantic.conint(gt=0, lt=4094) = None
    trunk_vlans: List[pydantic.conint(gt=0, lt=4094)] = None
    vlan_translations: List[VlanTranslation] = None
    portchannel_id: pydantic.conint(gt=0) = None
    members: List[str] = None

    @classmethod
    def from_switchport(cls, switchport):
        iface = cls(name=switchport.name)
        if switchport.lacp:
            iface.portchannel_id = switchport.portchannel_id
            iface.members = switchport.members
        return iface

    def add_trunk_vlan(self, vlan):
        if not self.trunk_vlans:
            self.trunk_vlans = []
        if vlan not in self.trunk_vlans:
            self.trunk_vlans.append(vlan)

    def add_vlan_translation(self, inside, outside):
        if not self.vlan_translations:
            self.vlan_translations = []
        for vt in self.vlan_translations:
            if vt.inside == inside and vt.outside == outside:
                return
        self.vlan_translations.append(VlanTranslation(inside=inside, outside=outside))


class SwitchConfigUpdate(pydantic.BaseModel):
    switch_name: str
    operation: OperationEnum

    vlans: List[Vlan] = None
    vxlan_maps: List[VXLANMapping] = None
    bgp: BGP = None
    ifaces: List[IfaceConfig] = None  # noqa: E701 (pyflakes bug)

    @classmethod
    def make_object_from_net_data(self, vxlan_map, net_host_map):
        pass

    def add_vlan(self, vlan, name=None):
        if self.vlans is None:
            self.vlans = []
        for v in self.vlans:
            if v.vlan == vlan:
                return
        self.vlans.append(Vlan(vlan=vlan, name=name))

    def add_vxlan_map(self, vni, vlan):
        if self.vxlan_maps is None:
            self.vxlan_maps = []
        for vm in self.vxlan_maps:
            if vm.vni == vni and vm.vlan == vlan:
                return
        self.vxlan_maps.append(VXLANMapping(vni=vni, vlan=vlan))

    def add_iface(self, iface):
        if self.ifaces is None:
            self.ifaces = []
        self.ifaces.append(iface)

        return iface

    def get_or_create_iface(self, switchport):
        if self.ifaces is None:
            self.ifaces = []

        for iface in self.ifaces:
            if iface.name == switchport.name:
                return iface

        iface = IfaceConfig.from_switchport(switchport)
        self.ifaces.append(iface)
        return iface


class SwitchConfigUpdateList:
    def __init__(self, operation, drv_conf):
        self.operation = operation
        self.drv_conf = drv_conf
        self.switch_config_updates = {}

    def get_or_create_switch(self, switch_name):
        if switch_name not in self.switch_config_updates:
            self.switch_config_updates[switch_name] = SwitchConfigUpdate(switch_name=switch_name,
                                                                         operation=self.operation)
        return self.switch_config_updates[switch_name]

    def add_binding_host_from_segment_to_config(self, binding_host, *args, **kwargs):
        # find binding host
        hg_config = self.drv_conf.get_hostgroup_by_host(binding_host)
        if hg_config is None:
            # FIXME: maybe don't use a value error here
            raise ValueError(f"Could not find binding host {binding_host}")

        return self.add_binding_host_to_config(hg_config, *args, **kwargs)

    def add_binding_host_to_config(self, hg_config, network_id, seg_vni, seg_vlan, trunk_vlan=None,
                                   keep_mapping=False, exclude_hosts=None, is_bgw=False):
        """Add binding host config to all required switches

        Given a hostgroup config this method generates and adds config to this
        config request. "Add" means that the config will be added, the overall
        operation (add, remove, replace) is determined by self.operation.

        Params:
         * keep_mapping: determines if the vlan-vni mapping is kept on op=remove/replace
         * exclude_hosts: hosts to exclude if a metagroup is being bound
         * is_bgw: bordergateway mode - no ifaces will be configured, bgp stanzas marked as bgw
        """
        add = self.operation == OperationEnum.add
        for switch_name, switchports in hg_config.iter_switchports(self.drv_conf, exclude_hosts=exclude_hosts):
            switch = self.drv_conf.get_switch_by_name(switch_name)
            scu = self.get_or_create_switch(switch.name)

            # add bgp stuff
            if add or not keep_mapping:
                if not scu.bgp:
                    sg = self.drv_conf.get_switchgroup_by_switch_name(switch.name)
                    scu.bgp = BGP(asn=sg.asn, asn_region=self.drv_conf.global_config.asn_region)
                scu.bgp.add_vlan(switch.get_rt(seg_vni), seg_vlan, seg_vni, bgw_mode=is_bgw)

            # vlan-vxlan mapping
            if add or not keep_mapping:
                scu.add_vlan(seg_vlan, network_id)
                scu.add_vxlan_map(seg_vni, seg_vlan)

            # interface config
            if not is_bgw:
                for sp in switchports:
                    iface = scu.get_or_create_iface(sp)
                    iface.add_trunk_vlan(seg_vlan)

                    if hg_config.direct_binding and not hg_config.role:
                        if trunk_vlan:
                            iface.add_vlan_translation(seg_vlan, trunk_vlan)
                        else:
                            iface.native_vlan = seg_vlan

    def execute(self, context):
        platform_updates = {}
        for scu in self.switch_config_updates.values():
            platform = self.drv_conf.get_switch_by_name(scu.switch_name).platform
            platform_updates.setdefault(platform, []).append(scu)

        if not platform_updates:
            return False

        for platform, updates in platform_updates.items():
            rpc_client = CCFabricSwitchAgentRPCClient.get_for_platform(platform)
            rpc_client.apply_config_update(context, updates)

        return True
