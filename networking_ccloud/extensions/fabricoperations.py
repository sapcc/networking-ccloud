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
from oslo_log import log as logging
from webob import exc as web_exc

import networking_ccloud.extensions

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
    def get_name(self):
        return "CC Fabric Driver API"

    @classmethod
    def get_alias(self):
        return "cc-fabric-api"

    @classmethod
    def get_description(self):
        return "CC Fabric driver API for extra driver functions"

    @classmethod
    def get_updated(self):
        """The timestamp when the extension was last updated."""
        return "2021-08-25T18:18:42+02:00"

    @classmethod
    def get_resources(self):
        """List of extensions.ResourceExtension extension objects.

        Resources define new nouns, and are accessible through URLs.
        """
        endpoints = []
        ep_name = 'cc-fabric'

        # status endpoint
        res = Resource(StatusController(), faults.FAULT_MAP)
        status_endpoint = extensions.ResourceExtension(f'{ep_name}/status', res)
        endpoints.append(status_endpoint)

        # config endpoint
        res = Resource(ConfigController(), faults.FAULT_MAP)
        config_endpoint = extensions.ResourceExtension(f'{ep_name}/config', res)
        endpoints.append(config_endpoint)

        return endpoints


def register_api_extension():
    extensions.register_custom_supported_check(Fabricoperations.get_alias(), lambda: True, True)
    extensions.append_api_extensions_path(networking_ccloud.extensions.__path__)


class StatusController(wsgi.Controller):
    def __init__(self):
        super(StatusController, self).__init__()

    @check_cloud_admin
    def index(self, request, **kwargs):
        return {"driver_reached": True}

    @check_cloud_admin
    def show(self, request, **kwargs):
        return "Soon"


class ConfigController(wsgi.Controller):
    def __init__(self):
        super(ConfigController, self).__init__()

    @check_cloud_admin
    def index(self, request, **kwargs):
        return {"driver_reached": True}

    @check_cloud_admin
    def show(self, request, **kwargs):
        return "Soon"
