# Copyright 2022 SAP SE
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

from neutron.db import segments_db
from neutron_lib.api.definitions import availability_zone as az_api
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib import constants as nl_const
from neutron_lib.plugins import directory
from neutron_lib.plugins.ml2 import api as ml2_api
from oslo_log import log as logging

from networking_ccloud.common import constants as cc_const
from networking_ccloud.db.db_plugin import CCDbPlugin
from networking_ccloud.ml2.agent.common import messages as agent_msg


LOG = logging.getLogger(__name__)


class FabricPlugin(CCDbPlugin):
    def __init__(self):
        super().__init__()

        self._plugin_property = None

    @property
    def _plugin(self):
        if self._plugin_property is None:
            self._plugin_property = directory.get_plugin()
        return self._plugin_property

    def allocate_and_configure_interconnects(self, context, network):
        """Allocate and configure interconnects for a network

        Returns two bools (new_allocation, error)
        """
        errors_found = False
        new_allocation = False

        # find top level segment
        network_id = network['id']
        top_segments = self.get_top_level_vxlan_segments(context, network_ids=[network_id])
        if network_id not in top_segments:
            LOG.error("Network %s has no top level segment (vxlan / physnet None), aborting transit/BGW scheduling",
                      network_id)
            return False, False
        segment_0 = top_segments[network_id]

        # allocate network interconnects (BGWs / Transits)
        az_hints = network.get(az_api.AZ_HINTS, [])
        created_transits = []
        scul = agent_msg.SwitchConfigUpdateList(agent_msg.OperationEnum.add, self.drv_conf)

        net_azs = az_hints or self.drv_conf.list_availability_zones()
        for az in net_azs:
            for device_type in (cc_const.DEVICE_TYPE_BGW, cc_const.DEVICE_TYPE_TRANSIT):
                if device_type == cc_const.DEVICE_TYPE_BGW and az_hints:
                    # we don't allocate BGWs for AZ-local networks
                    continue

                device_created, device = self.ensure_interconnect_for_network(context, device_type,
                                                                              network_id, az,
                                                                              only_own_az=bool(az_hints))
                if not device_created:
                    # no config needed, already allocated
                    continue

                # new device allocated, create a segment and add the host to scul
                device_hg = self.drv_conf.get_hostgroup_by_host(device.host)
                if not device_hg:
                    LOG.error("Could not bind device type %s host %s in network %s: Host not found in config",
                              device_type, device.host, network_id)
                    errors_found = True
                    continue

                device_physnet = device_hg.get_vlan_pool_name(self.drv_conf)
                segment_spec = {
                    ml2_api.NETWORK_TYPE: nl_const.TYPE_VLAN,
                    ml2_api.PHYSICAL_NETWORK: device_physnet,
                }
                device_segment = self._plugin.type_manager.allocate_dynamic_segment(context, network_id,
                                                                                    segment_spec)
                scul.add_binding_host_to_config(device_hg, network_id,
                                                segment_0[ml2_api.SEGMENTATION_ID],
                                                device_segment[ml2_api.SEGMENTATION_ID],
                                                is_bgw=device_type == cc_const.DEVICE_TYPE_BGW)
                if device_type == cc_const.DEVICE_TYPE_TRANSIT:
                    # add to notify list later on
                    created_transits.append((az, device.host, device_segment['id'], device_physnet))

                LOG.info("Allocated device %s to %s for network %s in az %s on vlan %s",
                         device_type, device.host, network_id, az, device_segment[ml2_api.SEGMENTATION_ID])
                new_allocation = True

        if new_allocation and not scul.execute(context):
            LOG.warning("Scheduling network interconnects for network %s yielded no config updates", network_id)

        for az, host, segment_id, physnet in created_transits:
            # notify others
            LOG.debug("Sending out notify for transit creation on %s for host %s az %s segment %s",
                      network_id, host, az, segment_id)
            payload_metadata = {
                'network_id': network_id,
                'availability_zone': az,
                'host': host,
                'segment_id': segment_id,
                'physical_network': physnet,
            }
            payload = events.DBEventPayload(context, metadata=payload_metadata)
            registry.publish(cc_const.CC_TRANSIT, events.AFTER_CREATE, self, payload=payload)

        return new_allocation, errors_found
