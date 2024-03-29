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

from operator import attrgetter
import sys
import time

from neutron.common import config as common_config
from neutron.conf.agent.common import register_agent_state_opts_helper
from neutron import manager
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import periodic_task
from prometheus_client import Histogram, start_http_server
from prometheus_client.utils import INF

from networking_ccloud.common.config import get_driver_config
from networking_ccloud.common import constants as cc_const
from networking_ccloud.common import exceptions as cc_exc
from networking_ccloud.ml2.agent.common import api as cc_agent_api
from networking_ccloud.ml2.agent.common import gmr
from networking_ccloud.ml2.agent.common import messages as agent_msg
from networking_ccloud.ml2.agent.common.service import ThreadedService
from networking_ccloud.ml2.agent.common.switch import FullSyncScheduled

LOG = logging.getLogger(__name__)


class CCFabricSwitchAgent(manager.Manager, cc_agent_api.CCFabricSwitchAgentAPI):
    """Baseclass for writing a CCFabric Switch Agent

    A Switch Agent will do the following things:
     * process driver RPC requests for creating/updating/deleting binding requests
     * run a syncloop to sync its switches
     * offer an API for introspection into its switches

    This base class implements basic switch abstraction via the CCSwitch model.
    """

    metrics_namespace = 'networking_ccloud_switch_agent'

    metric_switch_syncloop = Histogram(
        'syncloop', 'Switch syncloop duration',
        ['agent'], namespace=metrics_namespace,
        buckets=[round(30 + x ** 2.8) for x in range(12)] + [INF])
    metric_persist_configs_loop = Histogram(
        'persist_configs_loop', 'Persist configs duration',
        ['agent'], namespace=metrics_namespace,
        buckets=[round(10 + x ** 2) for x in range(12)] + [INF])
    metric_apply_config_update = Histogram(
        'apply_config_update', 'Apply config update duration (on agent)',
        ['agent'], namespace=metrics_namespace,
        buckets=[round(20 + x ** 2) for x in range(12)] + [INF])

    @classmethod
    def get_binary_name(cls):
        raise NotImplementedError

    @classmethod
    def get_agent_topic(cls):
        raise NotImplementedError

    @classmethod
    def get_switch_class(cls):
        raise NotImplementedError

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        gmr.register_thread_pool_stats(self)

        self._switches = []
        self._syncloop_enabled = True
        self.drv_conf = get_driver_config()

        self._def_labels = {
            'agent': self.get_binary_name(),
        }

    def _init_switches(self):
        """Init all switches the agent manages"""
        for sg_conf in self.drv_conf.switchgroups:
            managed_vlans = sg_conf.get_managed_vlans(self.drv_conf)
            az_suffix = self.drv_conf.global_config.get_availability_zone(sg_conf.availability_zone).suffix
            for switch_conf in sg_conf.members:
                if switch_conf.platform != self.get_switch_class().get_platform():
                    continue
                switch = self.get_switch_class()(switch_conf, self.drv_conf.global_config.asn_region, az_suffix,
                                                 managed_vlans, self.get_binary_name())
                LOG.debug("Adding switch %s with user %s to switchpool", switch, switch.user)
                self._switches.append(switch)

    def get_switch_by_name(self, name):
        for switch in self._switches:
            if switch.name == name:
                return switch
        return None

    def _start_prometheus(self):
        if not cfg.CONF.ml2_cc_fabric_agent.prometheus_enabled:
            return
        start_http_server(cfg.CONF.ml2_cc_fabric_agent.prometheus_listen_port,
                          cfg.CONF.ml2_cc_fabric_agent.prometheus_listen_address)

    def init_host(self):
        # usually called by neutron.service.Service at begin of start()
        LOG.info("Initializing agent %s with topic %s", self.get_binary_name(), self.get_agent_topic())
        self._init_switches()
        self._start_prometheus()

    def after_start(self):
        # usually called by neutron.service.Service at end of start()
        LOG.info("Agent started")
        LOG.debug("debugging on")

    def stop(self):
        # usually called by neutron.service.Service at end of stop()
        LOG.info("Agent shutting down")
        for switch in self._switches:
            switch._read_executor.shutdown()
            switch._write_executor.shutdown()
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
        start_time = time.time()
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
            try:
                result[switch_name] = future.result()
            except FullSyncScheduled as e:
                result[switch_name] = e.future.result()

        time_taken = time.time() - start_time
        self.metric_apply_config_update.labels(**self._def_labels).observe(time_taken)

        return result

    def get_syncloop_status(self, context):
        last_sync_times = {switch.name: switch.last_sync_time for switch in self._switches}
        return {'last_sync_time': last_sync_times, 'enabled': self._syncloop_enabled}

    def set_syncloop_enabled(self, context, enabled):
        self._syncloop_enabled = enabled

    @periodic_task.periodic_task(spacing=cfg.CONF.ml2_cc_fabric_agent.persist_config_loop_interval,
                                 run_immediately=False)
    def persist_switch_configs(self, context):
        start_time = time.time()
        LOG.info("Persisting config on all switches")
        futures = []
        for switch in sorted(self._switches, key=attrgetter('name')):
            futures.append(switch.persist_config())
        for future in futures:
            future.result()
        time_taken = time.time() - start_time
        self.metric_persist_configs_loop.labels(**self._def_labels).observe(time_taken)
        LOG.info("Persisting of all configs done in %.2fs", time_taken)

    @periodic_task.periodic_task(spacing=cfg.CONF.ml2_cc_fabric_agent.switch_syncloop_interval,
                                 run_immediately=False)
    def sync_all_switches(self, context):
        if not self._syncloop_enabled:
            LOG.warning("Switch syncloop is currently paused. You can reenable it via API or by restarting the agent")
            return
        start_time = time.time()
        LOG.info("Starting full switch sync on all switches")
        futures = []
        for switch in sorted(self._switches, key=attrgetter('name')):
            futures.append(switch.run_full_sync(context))
        for future in futures:
            future.result()
        time_taken = time.time() - start_time
        self.metric_switch_syncloop.labels(**self._def_labels).observe(time_taken)
        LOG.info("Syncing all switches done in %.2fs", time_taken)

    @periodic_task.periodic_task(spacing=60, enabled=cfg.CONF.ml2_cc_fabric_agent.prometheus_enabled)
    def collect_switch_metrics(self, context):
        for switch in self._switches:
            switch.collect_metrics(context)

    def backdoor_locals(self):

        def show_agent_queue_size():
            """Print out each switch with the queue size of their ThreadPoolExecutor"""
            for switch in sorted(self._switches, key=attrgetter('name')):
                print(f"{switch.name:<21} read {switch._read_executor._work_queue.qsize():>3} "
                      f"write {switch._write_executor._work_queue.qsize():>3}")

        return {
            'agent': self,
            'show_agent_queue_size': show_agent_queue_size,
        }
