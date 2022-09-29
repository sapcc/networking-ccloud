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
import inspect
import os
import random
import signal
import time

import manhole
from neutron.agent import rpc as agent_rpc
from neutron.common import profiler as neutron_profiler
from neutron import version
from neutron_lib.agent import constants as agent_consts
from neutron_lib.agent import topics
from neutron_lib import context
from oslo_config import cfg
from oslo_log import log as logging
from oslo_reports import guru_meditation_report as gmr
from oslo_service import loopingcall
from osprofiler import profiler

from networking_ccloud.ml2.agent.common.backdoor import BACKDOOR_LOCALS
from networking_ccloud.ml2.agent.common.loopingcall import monkeypatch_loopingcall
from networking_ccloud.ml2.agent.common.rpc import setup_rpc, shutdown_rpc

LOG = logging.getLogger(__name__)


backdoor_opts = [
    cfg.StrOpt('backdoor_socket',
               help="Enable manhole backdoor, using the provided path"
                    " as a unix socket that can receive connections. "
                    "Inside the path {pid} will be replaced with"
                    " the PID of the current process.")
]


@profiler.trace_cls("rpc")
class ThreadedService:
    """Bundle together the main parts to start a manager

    This class contains the extracted parts of neutron.service.Service,
    neutron_lib.rpc.Service and oslo_service.service that are necessary to
    bring up a manager for our use-case. We needed to extract them, because the
    mentioned classes are too coupled with eventlet/greenthreads.
    """
    def __init__(self, binary, topic, manager_cls, agent_type, host=None,
                 report_interval=None, periodic_interval=None,
                 periodic_fuzzy_delay=None):
        if not host:
            host = cfg.CONF.host
        if not binary:
            binary = os.path.basename(inspect.stack()[-1][1])
        if not topic:
            topic = binary.rpartition('neutron-')[2]
            topic = topic.replace("-", "_")
        if report_interval is None:
            report_interval = cfg.CONF.report_interval
        if periodic_interval is None:
            periodic_interval = cfg.CONF.periodic_interval
        if periodic_fuzzy_delay is None:
            periodic_fuzzy_delay = cfg.CONF.periodic_fuzzy_delay

        # this needs to run before we instantiate our manager in case the
        # manager wants to start loopingcalls in it's __init__()
        monkeypatch_loopingcall()

        neutron_profiler.setup(binary, host)

        # same as in neutron.cmd. Enable reports of tracebacks and config on
        # USR2 signal
        _version_string = version.version_info.release_string()
        gmr.TextGuruMeditation.setup_autorun(version=_version_string)

        signal.signal(signal.SIGHUP, self._signal_ignore)
        signal.signal(signal.SIGTERM, self._signal_graceful_exit)
        signal.signal(signal.SIGINT, self._signal_fast_exit)

        self.binary = binary
        self.topic = topic
        self.report_interval = report_interval
        self.periodic_interval = periodic_interval
        self.periodic_fuzzy_delay = periodic_fuzzy_delay
        self.manager = manager_cls()
        # set to the Connection instance containing the RPC servers
        self.conn = None
        # contains the started loopingcalls
        self.timers = []
        # state to report against Neutron if report_interval is > 0
        self.agent_state = {
            'binary': self.binary,
            'host': host,
            'agent_type': agent_type,
            'topic': self.topic,
            'configuration': {},
        }

        self.start_backdoor()

        # conf.register_opts(_options.service_opts)
        # TODO(jkulik) do we need to log all config options?
        # TODO(jkulik) do we need a graceful shutdown timeout?

    def _signal_ignore(self, signo, frame):
        LOG.info('Caught SIGHUP signal, ignoring it')

    def _signal_graceful_exit(self, signo, frame):
        LOG.info('Caught SIGTERM signal, stopping service')
        self.stop()
        self.wait()

    def _signal_fast_exit(self, signo, frame):
        LOG.info('Caught SIGINT signal, instantaneous exiting')
        os._exit(1)

    def start(self):
        """Start the service

        - let the manager run custom pre-start
        - start rpc listener/server
        - start _report_state background task
        - start periodic tasks runner
        - let manager run custom post-start
        """
        self.manager.init_host()
        self.conn = setup_rpc(self.topic, self.manager)

        if self.report_interval:
            self.state_rpc = agent_rpc.PluginReportStateAPI(topics.REPORTS)
            self.failed_report_state = False

            pulse = loopingcall.FixedIntervalLoopingCall(self.report_state)
            pulse.start(interval=self.report_interval,
                        initial_delay=self.report_interval)
            self.timers.append(pulse)

        if self.periodic_interval:
            if self.periodic_fuzzy_delay:
                initial_delay = random.randint(0, self.periodic_fuzzy_delay)
            else:
                initial_delay = None

            periodic = loopingcall.FixedIntervalLoopingCall(
                self.periodic_tasks)
            periodic.start(interval=self.periodic_interval,
                           initial_delay=initial_delay)
            self.timers.append(periodic)

        self.manager.after_start()

    def wait(self):
        """Wait for the service to get stopped"""
        # rpc-server is waited for in the Connection.close() already

        # wait for our loopingcalls to stop
        for x in self.timers:
            try:
                x.wait()
            except Exception:
                LOG.exception("Exception occurs when waiting for timer")

    def run(self):
        """Start the server and wait for any signals to arrive"""
        self.start()
        try:
            while True:
                # TODO(jkulik) we could check if the threads we expect to be alive are
                # still alive here, e.g. if our connection still has listening
                # servers and if our self.timers still have running threads
                time.sleep(1)
        finally:
            self.stop()
            self.wait()

    def stop(self):
        """Stop this service

        - stop the rpc-server
        - stop all timers/threads/periodics
        - run custom stop actions the manager needs to do
        """
        shutdown_rpc(self.conn)
        for x in self.timers:
            try:
                x.stop()
            except Exception:
                LOG.exception("Exception occurs when timer stops")
        self.timers = []
        self.manager.stop()

    def periodic_tasks(self, raise_on_error=False):
        """Tasks to be run at a periodic interval."""
        ctxt = context.get_admin_context()
        self.manager.periodic_tasks(ctxt, raise_on_error=raise_on_error)

    def report_state(self):
        try:
            if hasattr(self.manager, 'agent_configuration'):
                self.agent_state['configuration'] = self.manager.agent_configuration()

            ctx = context.get_admin_context_without_session()
            agent_status = self.state_rpc.report_state(
                ctx, self.agent_state, True)
            if agent_status == agent_consts.AGENT_REVIVED:
                LOG.info("Agent has just been revived")
        except Exception:
            self.failed_report_state = True
            LOG.exception("Failed reporting state!")
            return

        if self.failed_report_state:
            self.failed_report_state = False
            LOG.info("Successfully reported state after a previous failure.")

    def start_backdoor(self):
        """Start a backdoor shell for debugging connectable via UNIX socket"""
        cfg.CONF.register_opts(backdoor_opts)

        if not cfg.CONF.backdoor_socket:
            return

        try:
            socket_path = cfg.CONF.backdoor_socket.format(pid=os.getpid())
        except (KeyError, IndexError, ValueError) as e:
            socket_path = cfg.CONF.backdoor_socket
            LOG.warning(f"Could not apply format string to backdoor socket path ({e}) "
                        "- continuing with unformatted path")

        # add some commonly used functionality into the backdoor shell
        locals_ = BACKDOOR_LOCALS.copy()
        # let the Manager define additional functions for the backdoor shell
        if hasattr(self.manager, 'backdoor_locals'):
            locals_.update(self.manager.backdoor_locals())
        manhole.install(patch_fork=False, socket_path=socket_path, daemon_connection=True, locals=locals_,
                        redirect_stderr=False)
