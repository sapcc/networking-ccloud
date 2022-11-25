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
from neutron.extensions import tagging
from neutron import policy
from neutron import wsgi
from neutron_lib.api.definitions import external_net as extnet_api
from neutron_lib.api import extensions as api_extensions
from neutron_lib.api import faults
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib import exceptions as nl_exc
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_log import log as logging
from oslo_messaging import RemoteError
from webob import exc as web_exc

from networking_ccloud.common.config import get_driver_config
from networking_ccloud.common import constants as cc_const
import networking_ccloud.extensions
from networking_ccloud.ml2.agent.common.api import CCFabricSwitchAgentRPCClient
from networking_ccloud.ml2.agent.common import messages as agent_msg
from networking_ccloud.ml2.plugin import FabricPlugin


# we can't use __name__ for this logger, as stevedore only loads us as "fabricoperations"
LOG = logging.getLogger("networking_ccloud.extensions.fabricoperations")


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
    def _add_controller(cls, endpoints, ctrl, path, parent=None, path_prefix='/cc-fabric'):
        member_actions = getattr(ctrl, "MEMBER_ACTIONS", None)
        collection_actions = getattr(ctrl, "COLLECTION_ACTIONS", None)
        res = Resource(ctrl, faults.FAULT_MAP)
        ep = extensions.ResourceExtension(path, res, parent=parent, path_prefix=path_prefix,
                                          member_actions=member_actions, collection_actions=collection_actions)
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
        cls._add_controller(endpoints, FabricNetworksController(fabric_plugin), 'networks')
        cls._add_controller(endpoints, SwitchesController(fabric_plugin), 'switches')
        cls._add_controller(endpoints, SwitchgroupsController(fabric_plugin), 'switchgroups')
        cls._add_controller(endpoints, AgentSyncloopController(), 'agent-syncloop')

        return endpoints


def register_api_extension():
    extensions.register_custom_supported_check(Fabricoperations.get_alias(), lambda: True, True)
    extensions.append_api_extensions_path(networking_ccloud.extensions.__path__)


class FabricNetworksController(wsgi.Controller):
    """Show network info"""
    MEMBER_ACTIONS = {'diff': 'GET', 'sync': 'PUT', 'ensure_interconnects': 'PUT', 'os_config': 'GET',
                      'move_gateway_to_fabric': 'PUT'}

    def __init__(self, fabric_plugin):
        super().__init__()
        self.fabric_plugin = fabric_plugin
        self.drv_conf = get_driver_config()
        self.plugin = directory.get_plugin()
        self.tag_plugin = directory.get_plugin(tagging.TAG_PLUGIN_TYPE)

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
        scul = self._make_network_config(request.context, network_id)
        try:
            config_generated = scul.execute(request.context)
        except RemoteError as e:
            raise web_exc.HTTPInternalServerError(f"{e.exc_type} {e.value}")
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

    def _make_network_config(self, context, network_id):
        scul = self.fabric_plugin.make_network_config(context, network_id)
        if scul is None:
            raise web_exc.HTTPInternalServerError(f"The config for network {network_id} could not be generated "
                                                  "(see logs)")
        return scul

    @check_cloud_admin
    def os_config(self, request, **kwargs):
        network_id = kwargs.pop('id')
        self.plugin.get_network(request.context, network_id)

        scul = self.fabric_plugin.make_network_config(request.context, network_id)
        if not scul:
            return None

        configs = {}
        for switch_name, scu in scul.switch_config_updates.items():
            config = scu.dict(exclude_unset=True, exclude_defaults=True)
            del config['operation']
            configs[switch_name] = config

        return configs

    @check_cloud_admin
    def move_gateway_to_fabric(self, request, **kwargs):
        if cfg.CONF.ml2_cc_fabric.handle_all_l3_gateways:
            raise web_exc.HTTPConflict("Fabric driver is currently handling all gateways by default, "
                                       "moving gateways is only available when 'ml2_cc_fabric.handle_all_l3_gateways' "
                                       "is unset in config")
        # make sure network exists
        network_id = kwargs.pop('id')
        network = self.plugin.get_network(request.context, network_id)

        # ...and that it is an external network
        if not network[extnet_api.EXTERNAL]:
            raise web_exc.HTTPConflict(f"Network {network_id} is not an external network")

        # ...and that it is not already on the fabric
        if cc_const.L3_GATEWAY_TAG in network['tags']:
            raise web_exc.HTTPConflict(f"Network {network_id} was already moved to fabric")

        LOG.info("Starting move of l3 gateway for network %s to cc-fabric", network_id)

        # send event to other drivers
        payload_metadata = {
            'network_id': network_id,
            'move-to-cc-fabric': True,
        }
        payload = events.DBEventPayload(request.context, metadata=payload_metadata)
        registry.publish(cc_const.CC_NET_GW, events.BEFORE_UPDATE, self, payload=payload)

        # tag network
        self.tag_plugin.update_tag(request.context, "networks", network_id, cc_const.L3_GATEWAY_TAG)

        # send out network sync for this network (as now the tag has been set)
        scul = self._make_network_config(request.context, network_id)
        try:
            config_generated = scul.execute(request.context)
        except RemoteError as e:
            raise web_exc.HTTPInternalServerError(f"{e.exc_type} {e.value}")

        return {'sync_sent': config_generated}


class SwitchesController(wsgi.Controller):
    """List and show Switches from config"""
    MEMBER_ACTIONS = {'diff': 'GET', 'sync': 'PUT', 'sync_infra_networks': 'PUT', 'config': 'GET', 'os_config': 'GET'}
    COLLECTION_ACTIONS = {'create_all_portchannels': 'PUT'}

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
    def create_all_portchannels(self, request, **kwargs):
        scul = agent_msg.SwitchConfigUpdateList(agent_msg.OperationEnum.add, self.drv_conf)

        for hg in self.drv_conf.hostgroups:
            if hg.metagroup:
                continue
            for switchport in hg.members:
                if not switchport.lacp:
                    continue
                cfg_switch = scul.get_or_create_switch(switchport.switch)
                cfg_iface = cfg_switch.get_or_create_iface_from_switchport(switchport)
                # clear members, as they would cause a reference error on first config
                cfg_iface.members = []

        try:
            config_generated = scul.execute(request.context)
        except RemoteError as e:
            raise web_exc.HTTPInternalServerError(f"{e.exc_type} {e.value}")
        return {'sync_sent': config_generated}

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
        scul = self.fabric_plugin.make_switch_config(request.context, switch, sg)
        try:
            config_generated = scul.execute(request.context)
        except RemoteError as e:
            raise web_exc.HTTPInternalServerError(f"{e.exc_type} {e.value}")
        return {'sync_sent': config_generated}

    @check_cloud_admin
    def sync_infra_networks(self, request, **kwargs):
        switch, sg = self._get_switch(kwargs.pop('id'))

        LOG.info("Got API request for syncing infra networks of %s", switch.name)
        scul = agent_msg.SwitchConfigUpdateList(agent_msg.OperationEnum.replace, self.drv_conf)
        for hg in self.drv_conf.get_hostgroups_by_switches([switch.name]):
            if hg.infra_networks:
                scul.add_infra_networks_from_hostgroup(hg, sg)
            if hg.extra_vlans:
                scul.add_extra_vlans(hg)
        scul.clean_switches(switch.name)
        try:
            config_generated = scul.execute(request.context)
        except RemoteError as e:
            raise web_exc.HTTPInternalServerError(f"{e.exc_type} {e.value}")
        return {'sync_sent': config_generated}

    @check_cloud_admin
    def config(self, request, **kwargs):
        switch, sg = self._get_switch(kwargs.pop('id'))
        client = CCFabricSwitchAgentRPCClient.get_for_platform(switch.platform)
        config = client.get_switch_config(request.context, switches=[switch.name])
        config = config['switches'].get(switch.name)
        if config and 'operation' in config.get('config', {}):
            del config['config']['operation']
        return config

    @check_cloud_admin
    def os_config(self, request, **kwargs):
        switch, sg = self._get_switch(kwargs.pop('id'))
        config = self.fabric_plugin.make_switch_config(request.context, switch, sg)
        config = config.switch_config_updates.get(switch.name)
        if not config:
            return None
        config.sort()
        config = config.dict(exclude_unset=True, exclude_defaults=True)
        del config['operation']
        return dict(config=config)

    def _add_device_info(self, context, switches):
        for platform, switches in groupby(sorted(switches, key=itemgetter('platform')), key=itemgetter('platform')):
            switches = list(switches)
            switch_names = [s['name'] for s in switches]
            rpc_client = CCFabricSwitchAgentRPCClient.get_for_platform(platform)
            device_info = rpc_client.get_switch_status(context, switches=switch_names)['switches']
            for switch in switches:
                if switch['name'] in device_info:
                    di = device_info[switch['name']]
                    switch['device_info'] = {
                        'found': True,
                        'reachable': di['reachable'],
                        'version': di.get('version'),
                        'uptime': di.get('uptime'),
                        'model': di.get('model'),
                    }
                    if 'error' in di:
                        switch['device_error'] = di['error']
                else:
                    switch['device_info'] = {'found': False}


class SwitchgroupsController(wsgi.Controller):
    """List and show SwitchGroups from config"""

    MEMBER_ACTIONS = {'diff': 'GET', 'sync': 'PUT', 'sync_infra_networks': 'PUT', 'config': 'GET', 'os_config': 'GET'}

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

        LOG.info("Got API request for syncing switchgroup %s (%s)", sg.name, ", ".join(sw.name for sw in sg.members))
        scul = self.fabric_plugin.make_switchgroup_config(request.context, sg)
        try:
            config_generated = scul.execute(request.context)
        except RemoteError as e:
            raise web_exc.HTTPInternalServerError(f"{e.exc_type} {e.value}")
        return {'sync_sent': config_generated}

    @check_cloud_admin
    def sync_infra_networks(self, request, **kwargs):
        sg = self._get_switchgroup(kwargs.pop('id'))
        result = {}
        for member in sg.members:
            result[member.name] = self._swctrl.sync_infra_networks(request, id=member.name)
        return result

    @check_cloud_admin
    def config(self, request, **kwargs):
        sg = self._get_switchgroup(kwargs.pop('id'))
        result = {}
        for member in sg.members:
            result[member.name] = self._swctrl.config(request, id=member.name)
        return result

    @check_cloud_admin
    def os_config(self, request, **kwargs):
        sg = self._get_switchgroup(kwargs.pop('id'))
        result = {}
        for member in sg.members:
            result[member.name] = self._swctrl.os_config(request, id=member.name)
        return result

    def _get_switchgroup(self, sg_name):
        for sg in self.drv_conf.switchgroups:
            if sg.name == sg_name:
                return sg
        else:
            raise nl_exc.ObjectNotFound(id=sg_name)


class AgentSyncloopController(wsgi.Controller):
    def __init__(self):
        super().__init__()
        self.drv_conf = get_driver_config()

    @check_cloud_admin
    def index(self, request, **kwargs):
        result = {}
        for platform in self.drv_conf.get_platforms():
            rpc_client = CCFabricSwitchAgentRPCClient.get_for_platform(platform)
            result[platform] = rpc_client.get_syncloop_status(request.context)

        return result

    @check_cloud_admin
    def show(self, request, **kwargs):
        platform = kwargs.pop("id")
        if platform not in self.drv_conf.get_platforms():
            raise nl_exc.ObjectNotFound(id=platform)
        rpc_client = CCFabricSwitchAgentRPCClient.get_for_platform(platform)
        return rpc_client.get_syncloop_status(request.context)

    @check_cloud_admin
    def update(self, request, **kwargs):
        platform = kwargs.pop("id")
        if platform not in self.drv_conf.get_platforms():
            raise nl_exc.ObjectNotFound(id=platform)
        enabled = request.params.get('enabled')
        # FIXME: is this right? does put take parameters via url? or is there a different "default" way to do this?
        if enabled is None or enabled.lower() not in ('0', '1', 'false', 'true'):
            raise web_exc.HTTPBadRequest("Please provide the parameter 'enabled' with a value of 0/1/true/false")
        enabled = enabled.lower() in ('1', 'true')
        rpc_client = CCFabricSwitchAgentRPCClient.get_for_platform(platform)
        rpc_client.set_syncloop_enabled(request.context, enabled)

        return {'request_sent': True}


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
