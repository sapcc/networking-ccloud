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

import sys

from neutron.common import config as common_config
from neutron import manager
from neutron import service as neutron_service
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import service

from networking_ccloud.ml2.agent.common import api as cc_agent_api

LOG = logging.getLogger(__name__)


class CCFabricSwitchAgent(manager.Manager, cc_agent_api.CCFabricSwitchAgentAPI):
    """Baseclass for writing a CCFabric Switch Agent

    A Switch Agent will do the following things:
     * process driver RPC requests for creating/updating/deleting binding requests
     * run a syncloop to sync its switches
     * offer an API for introspection into its switches

    This base class implements basic switch abstraction via the CCSwitch model.
    """
    @classmethod
    def get_binary_name(cls):
        raise NotImplementedError

    @classmethod
    def get_agent_topic(cls):
        raise NotImplementedError

    def init_host(self):
        LOG.error("Initializing agent %s with topic %s", self.get_binary_name(), self.get_agent_topic())

    def after_start(self):
        LOG.info("Agent started")
        LOG.debug("debugging on")

    def stop(self):
        LOG.info("Agent shutting down")

    def initialize_service_hook(self, service):
        LOG.info("Service hook initialized from %s!", service)
        LOG.info("Hosts are %s", service.conn.servers[0]._target)

    @classmethod
    def run_agent_main(cls):
        common_config.init(sys.argv[1:])
        common_config.setup_logging()

        server = neutron_service.Service.create(
            binary=cls.get_binary_name(),
            topic=cls.get_agent_topic(),
            report_interval=0,
            periodic_interval=10,
            periodic_fuzzy_delay=10,
            manager=f'{cls.__module__}.{cls.__name__}')
        service.launch(cfg.CONF, server).wait()
