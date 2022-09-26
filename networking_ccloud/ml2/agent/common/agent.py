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
from neutron.conf.agent.common import register_agent_state_opts_helper
from neutron import manager
from oslo_config import cfg
from oslo_log import log as logging

from networking_ccloud.common.config import get_driver_config
from networking_ccloud.common import constants as cc_const
from networking_ccloud.common import exceptions as cc_exc
from networking_ccloud.ml2.agent.common import api as cc_agent_api
from networking_ccloud.ml2.agent.common import messages as agent_msg
from networking_ccloud.ml2.agent.common.service import ThreadedService

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

    def get_switch_class(cls):
        raise NotImplementedError

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._switches = []
        self.drv_conf = get_driver_config()

    def _init_switches(self):
        """Init all switches the agent manages"""
        for sg_conf in self.drv_conf.switchgroups:
            managed_vlans = sg_conf.get_managed_vlans(self.drv_conf)
            for switch_conf in sg_conf.members:
                if switch_conf.platform != self.get_switch_class().get_platform():
                    continue
                switch = self.get_switch_class()(switch_conf, self.drv_conf.global_config.asn_region, managed_vlans)
                LOG.debug("Adding switch %s with user %s to switchpool", switch, switch.user)
                self._switches.append(switch)

    def get_switch_by_name(self, name):
        for switch in self._switches:
            if switch.name == name:
                return switch
        return None

    def init_host(self):
        # usually called by neutron.service.Service at begin of start()
        LOG.info("Initializing agent %s with topic %s", self.get_binary_name(), self.get_agent_topic())
        self._init_switches()

    def after_start(self):
        # usually called by neutron.service.Service at end of start()
        LOG.info("Agent started")
        LOG.debug("debugging on")

    def stop(self):
        # usually called by neutron.service.Service at end of stop()
        LOG.info("Agent shutting down")
        for switch in self._switches:
            switch._executor.shutdown()
        LOG.info("Agent shut down")

    def initialize_rpc_hook(self, conn):
        # this is a method called in
        # networking_ccloud.ml2.agent.common.rpc.setup_rpc
        LOG.info("Service hook initialized from %s!", self)
        LOG.info("Hosts are %s", conn.servers[0]._target)

    @classmethod
    def run_agent_main(cls):
        register_agent_state_opts_helper(cfg.CONF)
        common_config.init(sys.argv[1:])
        common_config.setup_logging()

        server = ThreadedService(
            binary=cls.get_binary_name(),
            topic=cls.get_agent_topic(),
            report_interval=cfg.CONF.AGENT.report_interval,
            periodic_interval=10,
            periodic_fuzzy_delay=10,
            manager_cls=cls,
            agent_type=cc_const.AGENT_TYPE_CC_FABRIC)
        server.run()

    def run(self):
        LOG.info("Run called after start")

    def get_switch_status(self, context, switches=None):
        """Get status for specified or all switches this agent manages

         :param list switches: List of switch names or primary addresses to filter for
         """
        result = {'switches': {}}
        futures = []
        for switch in self._switches:
            if switches and switch.name not in switches:
                continue
            futures.append((switch.name, switch.get_switch_status()))

        for switch_name, future in futures:
            try:
                result['switches'][switch_name] = future.result()
                result['switches'][switch_name]['reachable'] = True
            except cc_exc.SwitchConnectionError as e:
                result['switches'][switch_name] = dict(reachable=False, error=str(e))
        return result

    def get_switch_config(self, context, switches):
        result = {'switches': {}}
        futures = []
        for switch in self._switches:
            if switches and switch.name not in switches:
                continue
            futures.append((switch.name, switch.get_config()))

        for switch_name, future in futures:
            try:
                config = future.result().dict(exclude_unset=True, exclude_defaults=True)
                result['switches'][switch_name] = dict(reachable=True, config=config)
            except cc_exc.SwitchConnectionError as e:
                result['switches'][switch_name] = dict(reachable=False, error=str(e))

        return result

    def apply_config_update(self, context, config):
        result = {}
        futures = []
        for update in config:
            update = agent_msg.SwitchConfigUpdate.parse_obj(update)
            switch = self.get_switch_by_name(update.switch_name)
            if not switch:
                result[update.switch_name] = None
                LOG.error("Could not find switch named %s on agent, ignoring '%s' update",
                          update.switch_name, update.operation)
                continue

            futures.append((update.switch_name, switch.apply_config_update(update)))

        for switch_name, future in futures:
            result[switch_name] = future.result()

        return result
