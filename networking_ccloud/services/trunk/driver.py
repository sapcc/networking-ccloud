# Copyright 2023 SAP SE
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

from neutron.services.trunk.drivers import base
from neutron_lib.api.definitions import port as p_api
from neutron_lib.api.definitions import portbindings as pb_api
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as nl_const
from neutron_lib.plugins import directory
from neutron_lib.services.trunk import constants as trunk_const
from oslo_config import cfg
from oslo_log import log as logging

from networking_ccloud.common.config import get_driver_config
from networking_ccloud.common import constants as cc_const
from networking_ccloud.common.exceptions import BadTrunkRequest
from networking_ccloud.common import helper
from networking_ccloud.ml2.plugin import FabricPlugin

LOG = logging.getLogger(__name__)

SUPPORTED_INTERFACES = (
    cc_const.VIF_TYPE_CC_FABRIC,
)
SUPPORTED_SEGMENTATION_TYPES = (
    trunk_const.SEGMENTATION_TYPE_VLAN,
)


class CCTrunkDriver(base.DriverBase):
    @property
    def is_loaded(self):
        try:
            return cc_const.CC_DRIVER_NAME in cfg.CONF.ml2.mechanism_drivers
        except cfg.NoSuchOptError:
            return False

    @classmethod
    def create(cls):
        return cls(cc_const.CC_DRIVER_NAME, SUPPORTED_INTERFACES, SUPPORTED_SEGMENTATION_TYPES,
                   can_trunk_bound_port=True)

    def _get_parent_port(self, context, parent_port_id):
        """Get parent port while checking it is compatible to our trunk driver

        Return None if this driver is not responsible for this trunk/port
        """
        port = self.core_plugin.get_port(context, parent_port_id)

        # FIXME: normally we also should be able to work with unbound trunks
        if not self.is_interface_compatible(port[pb_api.VIF_TYPE]):
            LOG.debug("Parent port %s vif type %s not compatible", parent_port_id, port[pb_api.VIF_TYPE])
            return None
        return port

    @registry.receives(resources.TRUNK_PLUGIN, [events.AFTER_INIT])
    def register(self, resource, event, trigger, payload=None):
        super().register(resource, event, trigger, payload=payload)

        self.core_plugin = directory.get_plugin()
        self.drv_conf = get_driver_config()
        self.fabric_plugin = FabricPlugin()

        registry.subscribe(self.trunk_valid_precommit, resources.TRUNK, events.PRECOMMIT_CREATE)
        registry.subscribe(self.trunk_create, resources.TRUNK, events.AFTER_CREATE)
        registry.subscribe(self.trunk_delete, resources.TRUNK, events.AFTER_DELETE)

        registry.subscribe(self.subport_valid_precommit, resources.SUBPORTS, events.PRECOMMIT_CREATE)
        registry.subscribe(self.subport_create, resources.SUBPORTS, events.AFTER_CREATE)
        registry.subscribe(self.subport_delete, resources.SUBPORTS, events.AFTER_DELETE)

    def trunk_valid_precommit(self, resource, event, trunk_plugin, payload):
        self.validate_trunk(payload.context, payload.desired_state, payload.desired_state.sub_ports)

    def subport_valid_precommit(self, resource, event, trunk_plugin, payload):
        self.validate_trunk(payload.context, payload.states[0], payload.metadata['subports'])

    def validate_trunk(self, context, trunk, subports):
        trunk_port = self._get_parent_port(context, trunk.port_id)
        if not trunk_port:
            LOG.debug("Not responsible for trunk on port %s", trunk.port_id)
            return

        # we can only trunk direct bindings
        trunk_host = helper.get_binding_host_from_port(trunk_port)
        LOG.info("Validating trunk for trunk %s port %s host %s", trunk.id, trunk.port_id, trunk_host)
        hg_config = self.drv_conf.get_hostgroup_by_host(trunk_host)
        if not hg_config:
            raise BadTrunkRequest(trunk_port_id=trunk.port_id,
                                  reason=f"No hostgroup config found for host {trunk_host}")

        if not hg_config.direct_binding:
            raise BadTrunkRequest(trunk_port_id=trunk.port_id,
                                  reason=f"Hostgroup {trunk_host} is not a direct binding hostgroup "
                                         "(maybe a metagroup?), only direct binding hostgroups can be trunked")

        if hg_config.role is not None:
            raise BadTrunkRequest(trunk_port_id=trunk.port_id,
                                  reason=f"Hostgroup {trunk_host} is of role {hg_config.role} "
                                         "and can therefore not be trunked")

        trunks_on_host = self.fabric_plugin.get_trunks_with_binding_host(context, trunk_host)
        trunks = set(trunks_on_host) - set([trunk.id])
        if trunks:
            raise BadTrunkRequest(trunk_port_id=trunk.port_id,
                                  reason=f"Host {trunk_host} already has trunk {' '.join(trunks)} connected to it")

        # subport validation
        parent_hg = hg_config.get_parent_metagroup(self.drv_conf)
        meta_hg_vlans = []
        if parent_hg:
            meta_hg_vlans = hg_config.get_any_switchgroup(self.drv_conf).get_managed_vlans(self.drv_conf,
                                                                                           with_infra_nets=True)

        subport_nets = {}
        # existing subports
        for existing_subport in trunk.sub_ports:
            subport_port = self.core_plugin.get_port(context, existing_subport.port_id)
            subport_nets[subport_port['network_id']] = existing_subport.port_id

        # new subports
        for subport in subports:
            # don't allow a network to be on two subports
            subport_port = self.core_plugin.get_port(context, subport.port_id)
            sp_net = subport_port['network_id']
            if sp_net in subport_nets and subport_nets[sp_net] != subport.port_id:
                raise BadTrunkRequest(trunk_port_id=trunk.port_id,
                                      reason=f"Network {sp_net} cannot be on two subports, "
                                             f"{subport_nets[sp_net]} and port {subport.port_id}")
            subport_nets[sp_net] = subport.port_id

            # for hostgroups that are in a metagroup we don't want to trunk anything that trunks toward a vlan id
            # that might be used by the metagroup
            if subport.segmentation_id in meta_hg_vlans:
                sg_name = hg_config.get_any_switchgroup(self.drv_conf).name
                raise BadTrunkRequest(trunk_port_id=trunk.port_id,
                                      reason=f"Subport {subport.port_id} segmentation id {subport.segmentation_id} "
                                             f"collides with vlan range of switchgroup {sg_name}")

    def trunk_create(self, resource, event, trunk_plugin, payload):
        trunk_port = self._get_parent_port(payload.context, payload.states[0].port_id)
        if not trunk_port:
            return
        self._bind_subports(payload.context, trunk_port, payload.states[0], payload.states[0].sub_ports)
        status = trunk_const.TRUNK_ACTIVE_STATUS if len(payload.states[0].sub_ports) else trunk_const.TRUNK_DOWN_STATUS
        payload.states[0].update(status=status)

    def trunk_delete(self, resource, event, trunk_plugin, payload):
        trunk_port = self._get_parent_port(payload.context, payload.states[0].port_id)
        if not trunk_port:
            return
        self._unbind_subports(payload.context, trunk_port, payload.states[0], payload.states[0].sub_ports)

    def subport_create(self, resource, event, trunk_plugin, payload):
        trunk_port = self._get_parent_port(payload.context, payload.states[0].port_id)
        if not trunk_port:
            return
        self._bind_subports(payload.context, trunk_port, payload.states[0], payload.metadata['subports'])

    def subport_delete(self, resource, event, trunk_plugin, payload):
        trunk_port = self._get_parent_port(payload.context, payload.states[0].port_id)
        if not trunk_port:
            return
        self._unbind_subports(payload.context, trunk_port, payload.states[0], payload.metadata['subports'])

    def _bind_subports(self, context, trunk_port, trunk, subports):
        for subport in subports:
            LOG.info("Adding subport %s trunk port %s of trunk %s", subport.port_id, trunk.port_id, trunk.id)
            binding_profile = trunk_port.get(pb_api.PROFILE)

            # note, that this information is only informational
            binding_profile[cc_const.TRUNK_PROFILE] = {
                'segmentation_type': subport.segmentation_type,
                'segmentation_id': subport.segmentation_id,
                'trunk_id': trunk.id,
            }

            port_data = {
                p_api.RESOURCE_NAME: {
                    pb_api.HOST_ID: trunk_port.get(pb_api.HOST_ID),
                    pb_api.VNIC_TYPE: trunk_port.get(pb_api.VNIC_TYPE),
                    pb_api.PROFILE: binding_profile,
                    'device_owner': trunk_const.TRUNK_SUBPORT_OWNER,
                    'device_id': trunk_port.get('device_id'),
                }
            }
            self.core_plugin.update_port(context, subport.port_id, port_data)
        if len(subports) > 0:
            trunk.update(status=trunk_const.TRUNK_ACTIVE_STATUS)

    def _unbind_subports(self, context, trunk_port, trunk, subports):
        for subport in subports:
            LOG.info("Removing subport %s trunk port %s of trunk %s", subport.port_id, trunk.port_id, trunk.id)
            binding_profile = trunk_port.get(pb_api.PROFILE)

            # note, that this is only informational
            if cc_const.TRUNK_PROFILE in binding_profile:
                del binding_profile[cc_const.TRUNK_PROFILE]

            port_data = {
                p_api.RESOURCE_NAME: {
                    pb_api.HOST_ID: None,
                    pb_api.VNIC_TYPE: None,
                    pb_api.PROFILE: binding_profile,
                    'device_owner': '',
                    'device_id': '',
                    'status': nl_const.PORT_STATUS_DOWN,
                },
            }
            self.core_plugin.update_port(context, subport.port_id, port_data)

            if len(trunk.sub_ports) - len(subports) > 0:
                trunk.update(status=trunk_const.TRUNK_ACTIVE_STATUS)
            else:
                LOG.info("Last subport was removed from trunk %s, setting it to state DOWN", trunk.id)
