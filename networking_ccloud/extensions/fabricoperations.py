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

from neutron.api import extensions
from neutron.api.v2.resource import Resource
from neutron import policy
from neutron import wsgi
from neutron_lib.api import extensions as api_extensions
from neutron_lib.api import faults
from neutron_lib import context
from neutron_lib import exceptions as nl_exc
from neutron_lib.plugins import directory
from oslo_log import log as logging
from webob import exc as web_exc

from networking_ccloud.common.config import get_driver_config
from networking_ccloud.db.db_plugin import CCDbPlugin
import networking_ccloud.extensions
from networking_ccloud.ml2.agent.common.api import CCFabricSwitchAgentRPCClient
from networking_ccloud.ml2.agent.common import messages as agent_msg


LOG = logging.getLogger(__name__)


ACCESS_RULE = "context_is_cloud_admin"


def check_cloud_admin(f):
    @functools.wraps(f)
    def wrapper(self, request, *args, **kwargs):
        if not policy.check(request.context, ACCESS_RULE, {'project_id': request.context.project_id}):
            raise web_exc.HTTPUnauthorized("{} required for access".format(ACCESS_RULE))
        return f(self, request, *args, **kwargs)
    return wrapper


class Fabricoperations(api_extensions.ExtensionDescriptor):
    """CC fabric ml2 driver API extensions"""
    # class name cannot be camelcase, needs to be just capitalized

    @classmethod
    def get_name(cls):
        return "CC Fabric Driver API"

    @classmethod
    def get_alias(cls):
        return "cc-fabric-api"

    @classmethod
    def get_description(cls):
        return "CC Fabric driver API for extra driver functions"

    @classmethod
    def get_updated(cls):
        """The timestamp when the extension was last updated."""
        return "2021-08-25T18:18:42+02:00"

    @classmethod
    def _add_controller(cls, endpoints, ctrl, path):
        res = Resource(ctrl, faults.FAULT_MAP)
        ep = extensions.ResourceExtension(path, res)
        endpoints.append(ep)

    @classmethod
    def get_resources(cls):
        """List of extensions.ResourceExtension extension objects.

        Resources define new nouns, and are accessible through URLs.
        """
        endpoints = []
        ep_name = 'cc-fabric'
        db = CCDbPlugin()

        cls._add_controller(endpoints, StatusController(), f'{ep_name}/status')
        cls._add_controller(endpoints, ConfigController(), f'{ep_name}/config')
        cls._add_controller(endpoints, AgentCheckController(), f'{ep_name}/agent-check')
        cls._add_controller(endpoints, SyncController(db), f'{ep_name}/sync')

        return endpoints


def register_api_extension():
    extensions.register_custom_supported_check(Fabricoperations.get_alias(), lambda: True, True)
    extensions.append_api_extensions_path(networking_ccloud.extensions.__path__)


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
        ctx = context.get_admin_context()
        for vendor in self.drv_conf.get_vendors():
            agent_resp = dict(vendor=vendor)
            try:
                rpc_client = CCFabricSwitchAgentRPCClient.get_for_vendor(vendor)
                agent_resp['response'] = rpc_client.ping_back_driver(ctx)
                agent_resp['success'] = True
            except Exception as e:
                agent_resp['response'] = f"{type(e.__class__.__name__)}: {e}"
                agent_resp['success'] = False
            resp.append(agent_resp)

        return resp


class SyncController(wsgi.Controller):
    def __init__(self, db):
        super().__init__()
        self.db = db
        self.drv_conf = get_driver_config()
        self.plugin = directory.get_plugin()

    @check_cloud_admin
    def index(self, request, **kwargs):
        return {"driver_reached": True}

    @check_cloud_admin
    def show(self, request, **kwargs):
        obj_type = kwargs.pop("id")
        # FIXME: Is this validation something we could do via an API scheme?
        if obj_type not in ("switches", "networks"):
            raise web_exc.HTTPBadRequest("Invalid sync option, please choose either switches or networks")

        objs = request.params.getall('obj')
        if not isinstance(objs, list) or not all(isinstance(e, str) for e in objs):
            raise web_exc.HTTPBadRequest("Payload must be a list of strings")

        if not objs:
            raise web_exc.HTTPBadRequest(f"Please provide at least one object identifier for the {obj_type} "
                                         f"you want to work with")

        # FIXME: command via GET is nothing we should do in the end product, fix this to proper API something
        # FIXME: write proper tests for this sync logic
        cmd = request.params.get('cmd', 'config')
        if cmd not in ('config', 'diff', 'sync'):
            raise web_exc.HTTPBadRequest(f"Cmd '{cmd}' is invalid, choose from config, diff, sync")

        filter_switches = None
        LOG.error("Test ctx %s sess %s", request.context, getattr(request.context, "session", None))
        if obj_type == "networks":
            # validate that all networks exist
            for network_id in objs:
                try:
                    self.plugin.get_network(request.context, network_id)
                except nl_exc.NetworkNotFound as e:
                    raise web_exc.HTTPBadRequest(str(e))

            # query db for physnets'n'stuff
            # create config update list for each bindinghost of each network
            scul = agent_msg.SwitchConfigUpdateList(agent_msg.OperationEnum.add, self.drv_conf)
            net_segments = self.db.get_hosts_on_segments(request.context, network_ids=objs)
        elif obj_type == "switches":
            # make sure switches exist and get their attached physnets
            physnets = []
            for switch in objs:
                if not self.drv_conf.get_switch_by_name(switch):
                    raise web_exc.HTTPBadRequest(f"Switch '{switch}' does not exist in current driver's switch config")
                # FIXME: can we have switches without a switchgroup?
                sg = self.drv_conf.get_switchgroup_by_switch_name(switch)
                physnets.append(sg.vlan_pool)

            filter_switches = objs
            # query db
            net_segments = self.db.get_hosts_on_segments(request.context, physical_networks=physnets)
            scul = agent_msg.SwitchConfigUpdateList(agent_msg.OperationEnum.replace, self.drv_conf)
        else:
            raise Exception(f"Unhandled mode '{obj_type}', should've been catched before - inform the developers -.-")

        top_segments = self.db.get_top_level_vxlan_segments(request.context, network_ids=list(net_segments.keys()))
        for network_id, segments in net_segments.items():
            if network_id not in top_segments:
                raise web_exc.HTTPInternalServerError(f"Network id {network_id} is missing its top level vxlan segment")

            segment_0 = top_segments[network_id]
            vni = segment_0['segmentation_id']

            for binding_host, segment_1 in segments.items():
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

        # FIXME: make sure no other switch jumped into this if the user requested a special set of switches
        if filter_switches is not None:
            switch_remove_list = set(sn for sn in scul.switch_config_updates if sn not in filter_switches)
            for switch_name in switch_remove_list:
                del scul.switch_config_updates[switch_name]

        if cmd == 'config':
            return {
                'switch_configs': {k: v.dict() for k, v in scul.switch_config_updates.items()},
            }
        elif cmd == 'diff':
            return {'error': 'Diff not implemented'}
        elif cmd == 'sync':
            if scul.execute():
                return {'sync': 'ok'}
            else:
                return {'sync': 'no_config'}
