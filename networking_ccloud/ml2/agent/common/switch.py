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

import abc
import datetime
from functools import wraps
import threading
import time

from futurist import ThreadPoolExecutor
from neutron_lib.context import get_admin_context
from oslo_concurrency import lockutils
from oslo_context import context
from oslo_log import log as logging

from networking_ccloud.ml2.driver_rpc_api import CCFabricDriverRPCClient

LOG = logging.getLogger(__name__)


class FullSyncScheduled(Exception):
    """Raised if a scheduled write-attempt was voluntarily interrupted because there's a full-sync in the queue

    Callers catching this exception should wait for the attached future
    attribute instead to know when their task finishes.
    """
    def __init__(self, *, future):
        super().__init__(self)
        self.future = future


def run_in_executor(type_, replacable_by_full_sync=False):
    """Decorator to run a method in the ThreadPoolExecutor of the class

    The wrapped method thus returns a futurist.Future now instead of its actual
    result.

    If replacable_by_full_sync is set, the decorated method will not run if
    there's a full-sync scheduled. Instead, it will raise FullSyncScheduled.
    Additionally, the decorated method will also not get scheduled, if there's
    already a full-sync scheduled. In that case, the wrapped method returns the
    scheduled full-sync's futurist.Future instead of its own. Callers have to
    be able to handle that.
    """
    if type_ != 'write' and replacable_by_full_sync:
        raise ValueError(f"@run_in_executor() called with replacable_by_full_sync=True on {type_} executor - "
                         "only 'write' is supported.")

    def decorator(fn):

        @wraps(fn)
        def wrapped(self, *args, **kwargs):
            executor = getattr(self, f'_{type_}_executor')

            current_context = context.get_current()

            if replacable_by_full_sync:
                # NOTE(jkulik): This is a very rough algorithm as a starting
                # point and up for discussion. It assumes that a full-sync is
                # a better/faster solution than running all the tasks in the
                # queue. It only holds true for tasks that are
                # replacable_by_full_sync, but the assumption is that these are
                # most of the tasks. Average runtime is skewed by having the
                # full-sync run in the same queue.
                avg_runtime = executor.statistics.average_runtime if executor.statistics.executed else 0
                qsize = executor._work_queue.qsize()
                full_sync_threshold = 120
                if qsize * avg_runtime > full_sync_threshold:
                    LOG.warning("Scheduling full-sync on %s for queue_size %s and avg runtime %s as the threshold "
                                "of %s is reached", self, qsize, avg_runtime, full_sync_threshold)
                    return self.run_full_sync(current_context.elevated() if current_context else get_admin_context())

                # if there's currently a full-sync scheduled and not started,
                # yet, we do not schedule our changes but rely on the full-sync
                # instead
                full_sync_future = self.get_full_sync_future()
                if full_sync_future is not None:
                    LOG.debug("Found scheduled full-sync on %s. Returning full-sync's Future instead", self)
                    return full_sync_future

            @wraps(fn)
            def extended_fn(self, *args, **kwargs):
                if current_context:
                    current_context.update_store()
                else:
                    # clear the current context of the thread set by the last
                    # function so we don't log stuff with the wrong context
                    try:
                        delattr(context._request_store, 'context')
                    except AttributeError:
                        pass

                if replacable_by_full_sync:
                    # short-circuit this function if there's a full-sync in the
                    # pipeline. our changes will be included there anyways
                    full_sync_future = self.get_full_sync_future()
                    if full_sync_future is not None:
                        LOG.debug("Returning early for scheduled full-sync on %s", self)
                        raise FullSyncScheduled(future=full_sync_future)

                return fn(self, *args, **kwargs)

            return executor.submit(extended_fn, self, *args, **kwargs)

        return wrapped

    return decorator


class SwitchBase(abc.ABC):
    def __init__(self, sw_conf, asn_region, managed_vlans, timeout=20, verify_ssl=False):
        self.sw_conf = sw_conf
        self.asn_region = asn_region
        self.managed_vlans = managed_vlans
        self.name = sw_conf.name
        self.host = sw_conf.host
        self.user = sw_conf.user
        self._password = sw_conf.password
        self.timeout = timeout
        self._verify_ssl = verify_ssl
        self._api = None
        self._read_executor = ThreadPoolExecutor(max_workers=5)
        self._write_executor = ThreadPoolExecutor(max_workers=1)
        self._full_sync_future_lock = threading.Lock()
        self._full_sync_future = None

        self._rpc_client = CCFabricDriverRPCClient()

        self._last_sync_time = None

    @classmethod
    @abc.abstractmethod
    def get_platform(cls):
        pass

    @property
    def api(self):
        if self._api is None:
            self.login()
        return self._api

    @property
    def last_sync_time(self):
        return self._last_sync_time

    @abc.abstractmethod
    def login(self):
        """Login into the switch - should set self._api"""
        pass

    def __str__(self):
        return f"{self.name} ({self.host})"

    def get_full_sync_future(self):
        with self._full_sync_future_lock:
            return self._full_sync_future

    @run_in_executor('read')
    def get_switch_status(self):
        return self._get_switch_status()

    def _get_switch_status(self):
        raise NotImplementedError

    @run_in_executor('read')
    def get_config(self):
        return self._get_config()

    def _get_config(self):
        raise NotImplementedError

    @run_in_executor('write', replacable_by_full_sync=True)
    def apply_config_update(self, config):
        with lockutils.lock(name=f"apply-config-update-{self.name}"):
            return self._apply_config_update(config)

    def _apply_config_update(self, config):
        raise NotImplementedError

    @run_in_executor('write')
    def persist_config(self):
        start_time = time.time()
        try:
            self._persist_config()
            LOG.debug("Switch config of %s saved in %.2f", self, time.time() - start_time)
        except Exception as e:
            LOG.error("Saving switch config of %s failed in %.2f: %s", self, time.time() - start_time, e)

    def _persist_config(self):
        raise NotImplementedError

    def run_full_sync(self, context):
        """Schedule a full sync for this switch or re-use an already scheduled one and return its future.

        Config will be fetched when the sync starts
        """

        @run_in_executor('write')
        def _in_thread_full_sync(self, context):
            # once the full sync starts, we remove access to the future,
            # because new state coming in might not be seen by a running
            # full-sync anymore and thus be missed
            with self._full_sync_future_lock:
                self._full_sync_future = None

            return self._run_full_sync(context)

        with self._full_sync_future_lock:
            # somebody else was already scheduled and didn't start, yet
            if self._full_sync_future is not None:
                LOG.debug("Full-sync already scheduled on %s. Returning other full-sync's Future instead", self)
                return self._full_sync_future

            self._full_sync_future = _in_thread_full_sync(self, context)
            return self._full_sync_future

    def _run_full_sync(self, context):
        start_time = time.time()
        try:
            config = self._rpc_client.get_switch_config(context, self.name)
            if not config:
                LOG.warning("Switch config of %s was empty, skipping it", self)
                return

            self._apply_config_update(config)
            self._last_sync_time = datetime.datetime.now()
            LOG.debug("Syncing switch config of %s succeeded in %.2f", self, time.time() - start_time)
        except Exception as e:
            LOG.exception("Syncing switch config of %s failed in %.2f: %s", self, time.time() - start_time, e)
