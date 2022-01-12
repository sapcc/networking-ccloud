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

from neutron import service
from neutron_lib.api.definitions import portbindings as pb_api
from neutron_lib import constants as nl_const
from neutron_lib.plugins import directory
from neutron_lib.plugins.ml2 import api as ml2_api
from neutron_lib import rpc as n_rpc
from oslo_log import log as logging

from networking_ccloud.common.config import get_driver_config, validate_ml2_vlan_ranges
from networking_ccloud.common import constants as cc_const
from networking_ccloud.common import exceptions as cc_exc
from networking_ccloud.common import helper
from networking_ccloud.db.db_plugin import CCDbPlugin
from networking_ccloud.extensions import fabricoperations
from networking_ccloud.ml2.agent.common.api import CCFabricSwitchAgentRPCClient
from networking_ccloud.ml2.agent.common import messages as agent_msg
from networking_ccloud.ml2.driver_rpc_api import CCFabricDriverAPI


LOG = logging.getLogger(__name__)


class CCFabricMechanismDriver(ml2_api.MechanismDriver, CCFabricDriverAPI):
    def __init__(self):
        # FIXME: not only check, but override segment vlan ranges
        # Currently we need to make sure that ml2_type_vlan.network_vlan_ranges is in sync
        # with the driver config, but overriding it would be better, as we know all values
        # that should be in there. This is a hard problem though. Options:
        # - force VlanTypeDriver to reload its allocations!
        #   VlanTypeDriver is loaded before us and parses config in __init__(). It does
        #   segment cleanup in its initialize(), thus we need to validate before it is
        #   initialized. If we could get a reference to it, we could force it to reload
        #   its config via its private method _parse_network_vlan_ranges(), but as we
        #   are called in Ml2Plugin.__init__() we cannot get a reference to the TypeManager.
        #   We could fix that by walking up the stacktrace, but we haven't been that
        #   desperate yet.
        # - implement custom config opt: this config opt parses the config and then
        #   overrides the network_vlan_ranges with the required values, way before
        #   any driver is instanciated
        # - implement own type-driver with own network type: we would then reverse segments
        #   for "cc-vlan", or something like that. Other than that same as VlanTypeDriver

        # this validation is done here so we can abport before VlanTypeDriver.initialize()
        # calls _sync_vlan_allocations(), which might wipe our vlans
        self.drv_conf = get_driver_config()
        validate_ml2_vlan_ranges(self.drv_conf)

        self.vif_details = {
            # allow ports without an IP to be bound
            pb_api.VIF_DETAILS_CONNECTIVITY: pb_api.CONNECTIVITY_L2,
        }

    def initialize(self):
        """Perform driver initialization.

        Called after all drivers have been loaded and the database has
        been initialized. No abstract methods defined below will be
        called prior to this method being called.
        """
        self._plugin_property = None
        validate_ml2_vlan_ranges(self.drv_conf)

        self.db = CCDbPlugin()

        # agent
        self._agents = {}

        fabricoperations.register_api_extension()

        LOG.info("CC-Fabric ml2 driver initialized")

    @property
    def _plugin(self):
        if self._plugin_property is None:
            self._plugin_property = directory.get_plugin()
        return self._plugin_property

    def start_rpc_listeners(self):
        """Start the RPC listeners.

        Most plugins start RPC listeners implicitly on initialization.  In
        order to support multiple process RPC, the plugin needs to expose
        control over when this is started.
        """
        LOG.debug("Starting cc-fabric internal driver RPC")
        self.conn = n_rpc.Connection()
        self.conn.create_consumer(cc_const.CC_DRIVER_TOPIC, [self])

        return self.conn.consume_in_threads()

    def get_workers(self):
        """Get any NeutronWorker instances that should have their own process

        Any driver that needs to run processes separate from the API or RPC
        workers, can return a sequence of NeutronWorker instances.
        """
        return [service.RpcWorker([self], worker_process_count=0)]

    def bind_port(self, context):
        """Attempt to bind a port.

        :param context: PortContext instance describing the port

        This method is called outside any transaction to attempt to
        establish a port binding using this mechanism driver. Bindings
        may be created at each of multiple levels of a hierarchical
        network, and are established from the top level downward. At
        each level, the mechanism driver determines whether it can
        bind to any of the network segments in the
        context.segments_to_bind property, based on the value of the
        context.host property, any relevant port or network
        attributes, and its own knowledge of the network topology. At
        the top level, context.segments_to_bind contains the static
        segments of the port's network. At each lower level of
        binding, it contains static or dynamic segments supplied by
        the driver that bound at the level above. If the driver is
        able to complete the binding of the port to any segment in
        context.segments_to_bind, it must call context.set_binding
        with the binding details. If it can partially bind the port,
        it must call context.continue_binding with the network
        segments to be used to bind at the next lower level.

        If the binding results are committed after bind_port returns,
        they will be seen by all mechanism drivers as
        update_port_precommit and update_port_postcommit calls. But if
        some other thread or process concurrently binds or updates the
        port, these binding results will not be committed, and
        update_port_precommit and update_port_postcommit will not be
        called on the mechanism drivers with these results. Because
        binding results can be discarded rather than committed,
        drivers should avoid making persistent state changes in
        bind_port, or else must ensure that such state changes are
        eventually cleaned up.

        Implementing this method explicitly declares the mechanism
        driver as having the intention to bind ports. This is inspected
        by the QoS service to identify the available QoS rules you
        can use with ports.
        """
        port = context.current
        binding_host = helper.get_binding_host_from_port(port)
        LOG.info("Got binding request for port %s with available segments %s",
                 port['id'], context.segments_to_bind)

        # check if host is in config, get hostgroup; if not, abort
        hg_config = self.drv_conf.get_hostgroup_by_host(binding_host)
        if hg_config is None:
            LOG.info("Driver is not responsible for binding_host %s on port %s, ignoring it",
                     binding_host, port['id'])
            return

        if len(context.segments_to_bind) < 1:
            LOG.warning("No segments found for port %s with host %s, ignoring it",
                        port['id'], binding_host)
            return

        if not context.binding_levels:
            # Port has not been bound to any segment --> top level binding --> hpb
            self._bind_port_hierarchical(context, binding_host, hg_config)
        elif hg_config.direct_binding:
            self._bind_port_direct(context, binding_host, hg_config)

    def _bind_port_hierarchical(self, context, binding_host, hg_config):
        """Do a top-level hierarchical portbinding"""
        # find the top segment (no physnet, type vxlan); there should be only one, but who knows
        for segment in context.segments_to_bind:
            if segment[ml2_api.NETWORK_TYPE] == nl_const.TYPE_VXLAN and segment[ml2_api.PHYSICAL_NETWORK] is None:
                break
        else:
            LOG.error("No usable segment found for hierarchicat binding for port %s, candidates were: %s",
                      context.current['id'], context.segments_to_bind)
            return

        # make sure the handover mode is supported (currently only vlan)
        if hg_config.handover_mode != cc_const.HANDOVER_VLAN:
            raise cc_exc.UnsupportedHandoverMode(hostgroup_name=hg_config.name, handover_mode=hg_config.handover_mode)

        # segment allocation
        segment_spec = {
            ml2_api.NETWORK_TYPE: nl_const.TYPE_VLAN,
            ml2_api.PHYSICAL_NETWORK: hg_config.get_vlan_pool_name(self.drv_conf),
        }
        next_segment = context.allocate_dynamic_segment(segment_spec)

        # config update (direct bindings are handled in the next step)
        if not hg_config.direct_binding:
            # send rpc call to agent (FIXME: cast or call?)
            # FIXME: can we only apply new config if the binding host is bound for the first time?
            self.handle_binding_host_changed(context._plugin_context, context.current['network_id'],
                                             binding_host, hg_config, segment, next_segment)

        # binding
        LOG.info("Binding port %s to toplevel segment %s, next segment is %s physnet %s segmentation id %s",
                 context.current['id'], segment['id'], next_segment['id'], next_segment[ml2_api.PHYSICAL_NETWORK],
                 next_segment[ml2_api.SEGMENTATION_ID])
        context.continue_binding(segment['id'], [next_segment])

    def _bind_port_direct(self, context, binding_host, hg_config):
        """Do a second-level direct portbinding"""
        config_physnet = hg_config.get_vlan_pool_name(self.drv_conf)
        # find matching segment
        for segment in context.segments_to_bind:
            if segment[ml2_api.PHYSICAL_NETWORK] == config_physnet:
                break
        else:
            LOG.error("Tried to directly bind port %s to physical network %s, but no matching "
                      "segment could be found, options were: %s",
                      context.current['id'], config_physnet, context.segments_to_bind)
            return

        # FIXME: trunk ports
        self.handle_binding_host_changed(context._plugin_context, context.current['network_id'], binding_host,
                                         hg_config, context.binding_levels[0][ml2_api.BOUND_SEGMENT], segment)

        vif_details = {}  # no vif-details needed yet
        context.set_binding(segment['id'], cc_const.VIF_TYPE_CC_FABRIC, vif_details, nl_const.ACTIVE)
        LOG.info("Port %s directly bound to segment %s physnet %s segmentation id %s",
                 context.current['id'], segment['id'], segment[ml2_api.PHYSICAL_NETWORK],
                 segment[ml2_api.SEGMENTATION_ID])

    def update_port_postcommit(self, context):
        """Update a port.

        :param context: PortContext instance describing the new
            state of the port, as well as the original state prior
            to the update_port call.

        Called after the transaction completes. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance.  Raising an exception will
        result in the deletion of the resource.

        update_port_postcommit is called for all changes to the port
        state. It is up to the mechanism driver to ignore state or
        state changes that it does not know or care about.
        """
        # FIXME: find out if bind_port() takes precedence
        old_host = helper.get_binding_host_from_port(context.original)
        new_host = helper.get_binding_host_from_port(context.current)
        if old_host != new_host:
            LOG.debug("Port %s changed binding host from %s to %s, calling remove operations on old host",
                      context.current['id'], old_host, new_host)
            self.driver_handle_binding_host_removed(context._plugin_context, context, context.original,
                                                    context.original_binding_levels[0][ml2_api.BOUND_SEGMENT],
                                                    context.original_binding_levels[1][ml2_api.BOUND_SEGMENT],
                                                    context.network.original['id'])

    def delete_port_postcommit(self, context):
        """Delete a port.

        :param context: PortContext instance describing the current
            state of the port, prior to the call to delete it.

        Called after the transaction completes. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance.  Runtime errors are not
        expected, and will not prevent the resource from being
        deleted.
        """
        self.driver_handle_binding_host_removed(context._plugin_context, context, context.current,
                                                context.binding_levels[0][ml2_api.BOUND_SEGMENT],
                                                context.binding_levels[1][ml2_api.BOUND_SEGMENT],
                                                context.network.current['id'])

    def driver_handle_binding_host_removed(self, context, port_context, port, segment_0, segment_1, network_id):
        binding_host = helper.get_binding_host_from_port(port)
        hg_config = self.drv_conf.get_hostgroup_by_host(binding_host)
        if hg_config is None:
            LOG.info("Binding host %s not found in config for removal request on port %s, ignoring",
                     binding_host, port['id'])
            return

        # 1. check if binding host is gone from network. if it's still there, nothing needs to be done
        #    as this method is only called postcommit we can trust the contents of the DB
        # 1.1 get info from db

        hosts_on_network = set(self.db.get_hosts_on_network(context, network_id))
        if binding_host in hosts_on_network:
            LOG.debug("Binding host %s still present on network %s, no need to remove anything for port %s",
                      binding_host, network_id, port['id'])
            return

        # 1.2 expand host if it's a metagroup, find out which hosts are gone
        # only iterate over switchports not on segment

        # 2. find out if physical_network is still in use
        # get all physnets of network, get physnet of hg of binding host, see if it's still there
        # get all binding hosts that have this physnet, see if any is
        # option 1: get vlanpool of host that left, get vlan pool of all other hosts on network, compare
        # option 2:
        port_vlan_pool = hg_config.get_vlan_pool_name(self.drv_conf)
        # import pdb; pdb.set_trace()

        for hg in self.drv_conf.get_hostgroups_by_hosts(hosts_on_network):
            if port_vlan_pool == hg.get_vlan_pool_name(self.drv_conf):
                keep_segment = True
                break
        else:
            # FIXME: should we done some extra checks for segment 1? is it owned by our driver? is it a vlan segment?
            LOG.info("Binding host %s of port %s was last on physnet %s network %s, deallocating segment %s",
                     binding_host, port['id'], port_vlan_pool, network_id, segment_1['id'])
            port_context.release_dynamic_segment(segment_1['id'])
            keep_segment = False

        # 3. config updates
        # FIXME: trunk?
        self.handle_binding_host_changed(context, network_id, binding_host, hg_config, segment_0, segment_1,
                                         add=False, keep_mapping=keep_segment, exclude_hosts=hosts_on_network)

    # ------------------ switch config snippet methods ------------------
    # FIXME: move this somewhere else
    def handle_binding_host_changed(self, context, network_id, binding_host, hg_config,
                                    segment_0, segment_1, trunk_vlan=None, force_update=False,
                                    add=True, keep_mapping=False, exclude_hosts=None):
        # FIXME: the logic of this method needs testing (i.e. written tests)
        LOG.debug("Handling config update (type %s) for binding host %s on %s",
                  "add" if add else "remove", binding_host, network_id)

        if not segment_0[ml2_api.NETWORK_TYPE] == nl_const.TYPE_VXLAN:
            raise ValueError(f"Port {context.current['id']} network {network_id} host {binding_host} "
                             f"not usable for config update: segment_0 ({segment_0['id']} is of type "
                             f"{segment_0[ml2_api.NETWORK_TYPE]}, expected {nl_const.TYPE_VXLAN}")

        if not segment_1[ml2_api.NETWORK_TYPE] == nl_const.TYPE_VLAN:
            raise ValueError(f"Port {context.current['id']} network {network_id} host {binding_host} "
                             f"not usable for config update: segment_1 ({segment_1['id']} is of type "
                             f"{segment_1[ml2_api.NETWORK_TYPE]}, expected {nl_const.TYPE_VXLAN}")

        if add and not force_update:
            # check if we need to send an update to the switch
            # the port is not fully bound yet (no bindings db commit), so we'll see what was bound before
            if binding_host in self.db.get_hosts_on_network(context, network_id):
                LOG.debug("Not sending out update for binding host %s - it is already bound and force_update=False",
                          binding_host)

        op = agent_msg.OperationEnum.add if add else agent_msg.OperationEnum.remove
        vendor_updates = {}
        seg_vni = segment_0[ml2_api.SEGMENTATION_ID]
        seg_vlan = segment_1[ml2_api.SEGMENTATION_ID]
        for switch_name, switchports in hg_config.iter_switchports(self.drv_conf, exclude_hosts=exclude_hosts):
            switch = self.drv_conf.get_switch_by_name(switch_name)
            sg = self.drv_conf.get_switchgroup_by_switch_name(switch.name)

            if add or not keep_mapping:
                bgp = agent_msg.BGP(asn=sg.asn)
                bgp.add_vlan(f"{switch.bgp_source_ip}:{seg_vni}", seg_vlan, seg_vni)
            else:
                bgp = None

            scu = agent_msg.SwitchConfigUpdate(switch_name=switch_name, operation=op, bgp=bgp)
            if add or not keep_mapping:
                scu.add_vlan(seg_vlan, network_id)
                scu.add_vxlan_map(seg_vni, seg_vlan)
            for sp in switchports:
                iface = agent_msg.IfaceConfig.from_switchport(sp)
                iface.add_trunk_vlan(seg_vlan)

                if hg_config.direct_binding:
                    if trunk_vlan:
                        iface.add_vlan_translation(seg_vlan, trunk_vlan)
                    else:
                        iface.native_vlan = seg_vlan
                scu.add_iface(iface)

            vendor_updates.setdefault(switch.vendor, []).append(scu)

        if not vendor_updates:
            LOG.warning("Update for host %s on %s yielded no config updates! add=%s, keep=%s, excl=%s",
                        binding_host, network_id, add, keep_mapping, exclude_hosts)

        for vendor, updates in vendor_updates.items():
            rpc_client = CCFabricSwitchAgentRPCClient.get_for_vendor(vendor)
            rpc_client.apply_config_update(context, updates)
