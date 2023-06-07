# Copyright 2023 SAP SE
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
import json
import logging
import time

from prometheus_client import Counter, Histogram
from pygnmi.client import gNMIclient, gNMIException

from networking_ccloud.common import exceptions as cc_exc


LOG = logging.getLogger(__name__)


class CCGNMIClient:
    metrics_namespace = 'networking_ccloud_switch_agent_switch_gnmi'

    DEFAULT_LABELS = ['platform', 'switch_name', 'switch_host', 'method']

    metric_api_action = Histogram(
        'api_action', 'GNMI API action duration',
        DEFAULT_LABELS + ['success'], namespace=metrics_namespace)
    metric_api_retry = Counter(
        'api_retry', 'GNMI API retry count',
        DEFAULT_LABELS, namespace=metrics_namespace)
    metric_api_retries_exhausted = Counter(
        'api_retries_exhausted', 'GNMI API retries exhausted count',
        DEFAULT_LABELS, namespace=metrics_namespace)

    def __init__(self, switch_name, host, port, platform, **kwargs):
        self._gnmi = gNMIclient(target=(host, port), **kwargs)
        self._switch_name = f"{switch_name} ({host})"
        self._platform = platform

        self._def_labels = {
            'platform': self._platform,
            'switch_name': switch_name,
            'switch_host': host,
        }

    def __repr__(self):
        return f"<{self.__class__.__name__} to {self._switch_name} ({self._platform})>"

    def connect(self, *args, **kwargs):
        try:
            self._gnmi.close()  # doesn't raise on already closed connection
        except AttributeError:
            # probably never connected (no channel present)
            pass
        # FIXME: currently this throws Except (not retriable)
        #   would possibly raise a ConnectionRefusedError
        #   ConnectionRefusedError: [Errno 111] Connection refused
        LOG.debug("Connecting to switch %s", self._switch_name)
        try:
            self._gnmi.connect(*args, **kwargs)
        except Exception as e:
            raise cc_exc.SwitchConnectionError(f"{self._switch_name} connect() {e.__class__.__name__} {e}")

    def _run_method(self, method, *args, retries=3, **kwargs):
        try:
            start_time = time.time()
            data = getattr(self._gnmi, method)(*args, **kwargs)
            time_taken = time.time() - start_time
            LOG.debug("Command %s() succeeded on %s in %.2fs", method, self._switch_name, time_taken)
            self.metric_api_action.labels(method=method, success=True, **self._def_labels).observe(time_taken)
            return data
        except gNMIException as e:
            time_taken = time.time() - start_time
            log_method = LOG.warning if retries > 0 else LOG.exception
            log_method("Command %s() failed on %s in %.2fs (retries left: %s): %s %s",
                       method, self._switch_name, time_taken, retries, e.__class__.__name__, str(e))
            self.metric_api_action.labels(method=method, success=False, **self._def_labels).observe(time_taken)

            cmd = [f"{method}("]
            if args:
                cmd.append(", ".join(map(json.dumps, args)))
            if kwargs:
                if args:
                    cmd.append(", ")
                cmd.append(", ".join(f"{k}={json.dumps(v)}" for k, v in kwargs.items()))
            cmd.append(")")
            cmd = "".join(cmd)
            LOG.debug("Failed command on %s was %s", self._switch_name, cmd)

            if isinstance(e.orig_exc, AttributeError):
                # module 'grpc' has no attribute '_channel', sometimes a first-connect problem
                LOG.info("Reconnecting %s because of %s %s", self._switch_name, e.__class__.__name__, str(e))
                self.connect()
            if retries > 0:
                self.metric_api_retry.labels(method=method, **self._def_labels).inc()
                time.sleep(0.5)
                return self._run_method(method, *args, retries=retries - 1, **kwargs)

            self.metric_api_retries_exhausted.labels(method=method, **self._def_labels).inc()
            raise cc_exc.SwitchConnectionError(f"{self._switch_name} {method}() {e.__class__.__name__} {e}")

    def get(self, prefix="", path=None, *args, unpack=True, single=True, **kwargs):
        data = self._run_method("get", prefix, path, *args, **kwargs)
        if data and unpack:
            data = data['notification']
            if path and len(path) > 1:
                data = [x['update'] for x in data]
            else:
                data = [data[0]['update']]

            def _unpack(entry):
                if single:
                    return entry[0]['val']
                else:
                    return [x['val'] for x in entry]

            data = [_unpack(e) for e in data]

            if not (path and len(path) > 1):
                data = data[0]

        return data

    def set(self, *args, retries=3, **kwargs):
        return self._run_method("set", *args, **kwargs)
