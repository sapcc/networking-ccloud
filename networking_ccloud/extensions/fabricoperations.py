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

import functools
from itertools import groupby
from operator import itemgetter

from neutron.api import extensions
from neutron.api.v2.resource import Resource
from neutron import policy
from neutron import wsgi
from neutron_lib.api import extensions as api_extensions
from neutron_lib.api import faults
from neutron_lib import exceptions as nl_exc
from neutron_lib.plugins import directory
from neutron_lib.plugins.ml2 import api as ml2_api
from oslo_log import log as logging
from webob import exc as web_exc

from networking_ccloud.common.config import get_driver_config
from networking_ccloud.common import constants as cc_const
import networking_ccloud.extensions
from networking_ccloud.ml2.agent.common.api import CCFabricSwitchAgentRPCClient
from networking_ccloud.ml2.agent.common import messages as agent_msg
from networking_ccloud.ml2.plugin import FabricPlugin


LOG = logging.getLogger(__name__)


ACCESS_RULE = "context_is_cloud_admin"


def check_cloud_admin(f):
    @functools.wraps(f)
    def wrapper(self, request, *args, **kwargs):
        if not policy.check(request.context, ACCESS_RULE, {'project_id': request.context.project_id}):
            raise web_exc.HTTPUnauthorized("{} required for access".format(ACCESS_RULE))
        return f(self, request, *args, **kwargs)
    return wrapper


class FabricAPIDefinition:
    NAME = "CC Fabric Driver API"
    ALIAS = "cc-fabric-api"
    DESCRIPTION = "CC Fabric driver API for extra driver functions"
    UPDATED_TIMESTAMP = "2021-08-25T18:18:42+02:00"
    RESOURCE_ATTRIBUTE_MAP = {}
    SUB_RESOURCE_ATTRIBUTE_MAP = {}
    REQUIRED_EXTENSIONS = []
    OPTIONAL_EXTENSIONS = []


class Fabricoperations(api_extensions.APIExtensionDescriptor):
    """CC fabric ml2 driver API extensions"""
    # class name cannot be camelcase, needs to be just capitalized

    api_definition = FabricAPIDefinition

    @classmethod
    def _add_controller(cls, endpoints, ctrl, path, parent=None, path_prefix='cc-fabric'):
        member_actions = getattr(ctrl, "MEMBER_ACTIONS", None)
        res = Resource(ctrl, faults.FAULT_MAP)
        ep = extensions.ResourceExtension(path, res, parent=parent, path_prefix=path_prefix,
                                          member_actions=member_actions)
        endpoints.append(ep)

    @classmethod
    def get_resources(cls):
        """List of extensions.ResourceExtension extension objects.

        Resources define new nouns, and are accessible through URLs.
        """
        endpoints = []
        fabric_plugin = FabricPlugin()

        cls._add_controller(endpoints, StatusController(), 'status')
        cls._add_controller(endpoints, ConfigController(), 'config')
        cls._add_controller(endpoints, AgentCheckController(), 'agent-check')

        # "the new ones"
        cls._add_controller(endpoints, FabricNetworksController(fabric_plugin), 'networks')
        cls._add_controller(endpoints, SwitchesController(fabric_plugin), 'switches')
        cls._add_controller(endpoints, SwitchgroupsController(fabric_plugin), 'switchgroups')

        return endpoints


def register_api_extension():
    extensions.register_custom_supported_check(Fabricoperations.get_alias(), lambda: True, True)
    extensions.append_api_extensions_path(networking_ccloud.extensions.__path__)


class FabricNetworksController(wsgi.Controller):
    """Show network info"""
    MEMBER_ACTIONS = {'diff': 'GET', 'sync': 'PUT', 'ensure_interconnects': 'PUT'}

    def __init__(self, fabric_plugin):
        super().__init__()
        self.fabric_plugin = fabric_plugin
        self.drv_conf = get_driver_config()
        self.plugin = directory.get_plugin()

    @check_cloud_admin
    def index(self, request, **kwargs):
        raise web_exc.HTTPBadRequest("Index not available for this resource")

    @check_cloud_admin
    def update(self, request, **kwargs):
        raise web_exc.HTTPBadRequest("update not available for this resource")

    @check_cloud_admin
    def show(self, request, **kwargs):
        """Show what we know about a network"""
        # make sure network exists
        network_id = kwargs.pop('id')
        net = self.plugin.get_network(request.context, network_id)

        # fetch interconnects
        interconnects_db = self.fabric_plugin.get_interconnects(request.context, network_id=network_id)
        interconnects = [dict(host=i.host, device_type=i.device_type, availability_zone=i.availability_zone)
                         for i in interconnects_db]
        # FIXME: check if network has all the interconnects it needs

        # fetch binding hosts
        hosts_db = self.fabric_plugin.get_hosts_on_segments(request.context, network_ids=[network_id])
        hosts = [h for h in hosts_db.get(network_id, [])]

        # FIXME: add on which switches / switchgroups the network is present

        return {
            'id': net['id'],
            'hosts': hosts,
            'interconnects': interconnects,
        }

    @check_cloud_admin
    def diff(self, request, **kwargs):
        # make sure network exists
        network_id = kwargs.pop('id')
        self.plugin.get_network(request.context, network_id)
        # FIXME: get config from device, diff them

        print("Got diff request", request, kwargs)
        raise web_exc.HTTPNotImplemented("Network diff is not implemented yet")

    @check_cloud_admin
    def sync(self, request, **kwargs):
        # make sure network exists
        network_id = kwargs.pop('id')
        self.plugin.get_network(request.context, network_id)

        LOG.info("Got API request for syncing network %s", network_id)
        scul = self._make_config_from_network(request.context, network_id)
        config_generated = scul.execute(request.context)
        return {'sync_sent': config_generated}

    @check_cloud_admin
    def ensure_interconnects(self, request, **kwargs):
        # make sure network exists
        network_id = kwargs.pop('id')
        network = self.plugin.get_network(request.context, network_id)

        created, errors = self.fabric_plugin.allocate_and_configure_interconnects(request.context, network)

        return {
            'network_id': network_id,
            'interconnects_allocated': created,
            'error_on_allocation': errors,
        }

    def _make_config_from_network(self, context, network_id):
        scul = agent_msg.SwitchConfigUpdateList(agent_msg.OperationEnum.add, self.drv_conf)

        top_segments = self.fabric_plugin.get_top_level_vxlan_segments(context, network_ids=[network_id])
        if network_id not in top_segments:
            raise web_exc.HTTPInternalServerError(f"Network id {network_id} is missing its top level vxlan segment")
        vni = top_segments[network_id]['segmentation_id']

        net_segments = self.fabric_plugin.get_hosts_on_segments(context, network_ids=[network_id])
        if network_id not in net_segments:
            raise web_exc.HTTPInternalServerError(f"Network id {network_id} has segments attached to it")

        for binding_host, segment_1 in net_segments[network_id].items():
            vlan = segment_1['segmentation_id']
            hg_config = self.drv_conf.get_hostgroup_by_host(binding_host)
            if not hg_config:
                LOG.error("Got a port binding for binding host %s in network %s, which was not found in config",
                          binding_host, network_id)
                continue
            # FIXME: handle trunk_vlans
            # FIXME: exclude_hosts
            # FIXME: direct binding hosts? are they included?
            scul.add_binding_host_to_config(hg_config, network_id, vni, vlan)

        interconnects = self.fabric_plugin.get_interconnects(context, network_id=network_id)
        for device in interconnects:
            device_hg = self.drv_conf.get_hostgroup_by_host(device.host)
            if not device_hg:
                LOG.error("Could not bind device type %s host %s in network %s: Host not found in config",
                          device.device_type, device.host, network_id)
                continue

            device_physnet = device_hg.get_vlan_pool_name(self.drv_conf)
            device_segment = self.fabric_plugin.get_segment_by_host(context, network_id, device_physnet)
            if not device_segment:
                LOG.error("Missing network segment for interconnect %s physnet %s in network %s",
                          device.host, device_physnet, network_id)
                continue

            scul.add_binding_host_to_config(device_hg, network_id, vni, device_segment[ml2_api.SEGMENTATION_ID],
                                            is_bgw=device.device_type == cc_const.DEVICE_TYPE_BGW)

        return scul


class SwitchesController(wsgi.Controller):
    """List and show Switches from config"""
    MEMBER_ACTIONS = {'diff': 'GET', 'sync': 'PUT', 'sync_infra_networks': 'PUT'}

    def __init__(self, fabric_plugin):
        super().__init__()
        self.fabric_plugin = fabric_plugin
        self.drv_conf = get_driver_config()

    @classmethod
    def _make_switch_dict(cls, switch, sg):
        return dict(name=switch.name, host=switch.host, user=switch.user, platform=switch.platform,
                    availability_zone=sg.availability_zone, switchgroup=sg.name)

    def _get_switch(self, switch_name):
        for sg in self.drv_conf.switchgroups:
            for switch in sg.members:
                if switch.name == switch_name:
                    return switch, sg
        else:
            raise nl_exc.ObjectNotFound(id=switch_name)

    @check_cloud_admin
    def index(self, request, **kwargs):
        switches = [self._make_switch_dict(switch, sg) for sg in self.drv_conf.switchgroups for switch in sg.members]

        if request.params.get('device_info'):
            self._add_device_info(request.context, switches)

        return switches

    @check_cloud_admin
    def show(self, request, **kwargs):
        switch = self._make_switch_dict(*self._get_switch(kwargs.pop('id')))
        if request.params.get('device_info'):
            self._add_device_info(request.context, [switch])

        return switch

    @check_cloud_admin
    def diff(self, request, **kwargs):
        switch, sg = self._get_switch(kwargs.pop('id'))

        print("Got diff request", request, kwargs)
        raise web_exc.HTTPNotImplemented("Switch diff is not implemented yet")

    @check_cloud_admin
    def sync(self, request, **kwargs):
        switch, sg = self._get_switch(kwargs.pop('id'))

        LOG.info("Got API request for syncing switch %s", switch.name)
        scul = self._make_switch_config(request.context, switch, sg)
        config_generated = scul.execute(request.context)
        return {'sync_sent': config_generated}

    @check_cloud_admin
    def sync_infra_networks(self, request, **kwargs):
        switch, sg = self._get_switch(kwargs.pop('id'))

        LOG.info("Got API request for syncing infra networks of %s", switch.name)
        scul = agent_msg.SwitchConfigUpdateList(agent_msg.OperationEnum.replace, self.drv_conf)
        for hg in self.drv_conf.get_hostgroups_by_switch(switch.name):
            if hg.infra_networks:
                for inet in hg.infra_networks:
                    # FIXME: exclude hosts
                    scul.add_binding_host_to_config(hg, inet.name, inet.vni, inet.vlan)
        self._clean_switches(scul, switch)
        config_generated = scul.execute(request.context)
        return {'sync_sent': config_generated}

    def _add_device_info(self, context, switches):
        for platform, switches in groupby(sorted(switches, key=itemgetter('platform')), key=itemgetter('platform')):
            switches = list(switches)
            switch_names = [s['name'] for s in switches]
            rpc_client = CCFabricSwitchAgentRPCClient.get_for_platform(platform)
            device_info = rpc_client.get_switch_status(context, switches=switch_names)
            for switch in switches:
                if switch['name'] in device_info:
                    di = device_info[switch['name']]
                    switch['device_info'] = {
                        'found': True,
                        'reachable': di['reachable'],
                        'version': di.get('version'),
                        'uptime': di.get('uptime'),
                    }
                    if 'error' in di:
                        switch['device_error'] = di['error']
                else:
                    switch['device_info'] = {'found': False}

    def _make_switch_config(self, context, switch, sg):
        scul = agent_msg.SwitchConfigUpdateList(agent_msg.OperationEnum.replace, self.drv_conf)

        # physnets of this switch, which is the switch's switchgroup's vlan pool
        physnets = [sg.vlan_pool]

        # get all binding hosts bound onto that switch
        #   + interconnects
        #   + infra networks
        net_segments = self.fabric_plugin.get_hosts_on_segments(context, physical_networks=physnets)
        top_segments = self.fabric_plugin.get_top_level_vxlan_segments(context, network_ids=list(net_segments.keys()))
        scul.add_segments(net_segments, top_segments)

        for hg in self.drv_conf.get_hostgroups_by_switch(switch.name):
            if hg.infra_networks:
                for inet in hg.infra_networks:
                    # FIXME: exclude hosts
                    scul.add_binding_host_to_config(hg, inet.name, inet.vni, inet.vlan)
            if hg.role:
                # transits/BGWs don't have bindings, so bind all physnets
                # find all physnets or interconnects scheduled
                interconnects = self.fabric_plugin.get_interconnects(context, host=hg.binding_hosts[0])
                scul.add_interconnects(context, self.fabric_plugin, interconnects)

        self._clean_switches(scul, switch)
        return scul

    def _clean_switches(self, scul, switch):
        # make sure we only sync that one switch
        for cfg_switch in list(scul.switch_config_updates):
            if cfg_switch != switch.name:
                del scul.switch_config_updates[cfg_switch]


class SwitchgroupsController(wsgi.Controller):
    """List and show SwitchGroups from config"""

    MEMBER_ACTIONS = {'diff': 'GET', 'sync': 'PUT', 'sync_infra_networks': 'PUT'}

    def __init__(self, fabric_plugin):
        super().__init__()
        self.fabric_plugin = fabric_plugin
        self.drv_conf = get_driver_config()
        self._swctrl = SwitchesController(fabric_plugin)

    def _make_sg_dict(self, sg, request):
        return dict(name=sg.name, availability_zone=sg.availability_zone,
                    members=[self._swctrl.show(request, id=s.name) for s in sg.members])

    @check_cloud_admin
    def index(self, request, **kwargs):
        return [self._make_sg_dict(sg, request) for sg in self.drv_conf.switchgroups]

    @check_cloud_admin
    def show(self, request, **kwargs):
        sg = self._get_switchgroup(kwargs.pop('id'))
        return self._make_sg_dict(sg, request)

    @check_cloud_admin
    def diff(self, request, **kwargs):
        sg = self._get_switchgroup(kwargs.pop('id'))
        result = {}
        for member in sg.members:
            result[member.name] = self._swctrl.diff(request, id=member.name)
        return result

    @check_cloud_admin
    def sync(self, request, **kwargs):
        sg = self._get_switchgroup(kwargs.pop('id'))
        result = {}
        for member in sg.members:
            result[member.name] = self._swctrl.sync(request, id=member.name)
        return result

    @check_cloud_admin
    def sync_infra_networks(self, request, **kwargs):
        sg = self._get_switchgroup(kwargs.pop('id'))
        result = {}
        for member in sg.members:
            result[member.name] = self._swctrl.sync_infra_networks(request, id=member.name)
        return result

    def _get_switchgroup(self, sg_name):
        for sg in self.drv_conf.switchgroups:
            if sg.name == sg_name:
                return sg
        else:
            raise nl_exc.ObjectNotFound(id=sg_name)


class StatusController(wsgi.Controller):
    def __init__(self):
        super().__init__()

    @check_cloud_admin
    def index(self, request, **kwargs):
        return {"driver_reached": True}

    @check_cloud_admin
    def show(self, request, **kwargs):
        return "Soon"


class ConfigController(wsgi.Controller):
    def __init__(self):
        super().__init__()

    @check_cloud_admin
    def index(self, request, **kwargs):
        return {"driver_reached": True}

    @check_cloud_admin
    def show(self, request, **kwargs):
        return "Soon"


class AgentCheckController(wsgi.Controller):
    def __init__(self):
        super().__init__()
        self.drv_conf = get_driver_config()

    @check_cloud_admin
    def index(self, request, **kwargs):
        LOG.info("agent-check request %s kwargs %s", request, kwargs)
        resp = []
        for platform in self.drv_conf.get_platforms():
            agent_resp = dict(platform=platform)
            try:
                rpc_client = CCFabricSwitchAgentRPCClient.get_for_platform(platform)
                agent_resp['response'] = rpc_client.ping_back_driver(request.context)
                agent_resp['success'] = True
            except Exception as e:
                agent_resp['response'] = f"{type(e.__class__.__name__)}: {e}"
                agent_resp['success'] = False
            resp.append(agent_resp)

        return resp
