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
from neutron_lib import rpc as n_rpc
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_messaging.rpc import dispatcher

LOG = logging.getLogger(__name__)


def threaded_get_server(target, endpoints, serializer=None):
    """Get a new RPC server reference.

    Basically the same as neutron_lib.rpc.get_server() but uses threading
    instead of eventlet.

    :param target: The target for the new RPC server.
    :param endpoints: The endpoints for the RPC server.
    :param serializer: The optional serialize to use for the RPC server.
    :returns: A new RPC server reference.
    """
    if n_rpc.TRANSPORT is None:
        raise AssertionError(_("'neutron_lib.rpc.TRANSPORT' must not be None"))
    serializer = n_rpc.RequestContextSerializer(serializer)
    access_policy = dispatcher.DefaultRPCAccessPolicy
    return oslo_messaging.get_rpc_server(n_rpc.TRANSPORT, target, endpoints,
                                         'threading', serializer,
                                         access_policy=access_policy)


class ThreadedConnection(n_rpc.Connection):
    """A utility class that manages a collection of RPC servers.

    Overwrites the parent's create_consumer() to call our own
    threaded_get_server().
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def create_consumer(self, topic, endpoints, fanout=False):
        target = oslo_messaging.Target(
            topic=topic, server=cfg.CONF.host, fanout=fanout)
        server = threaded_get_server(target, endpoints)
        self.servers.append(server)


def setup_rpc(topic, manager):
    """Create an RPC server for the given manager

    This code lives similarly in neutron_lib.rpc.Service, but we cannot use it,
    as we need our own ThreadedConnection to be created and we cannot inherit
    from oslo_service.service.Service as this also uses eventlet.
    """
    conn = ThreadedConnection()

    LOG.debug("Creating Consumer connection for Service %s", topic)

    endpoints = [manager]

    conn.create_consumer(topic, endpoints)

    # Hook to allow the manager to do other initializations after
    # the rpc connection is created.
    if callable(getattr(manager, 'initialize_rpc_hook', None)):
        manager.initialize_rpc_hook(conn)

    # Consume from all consumers in threads
    conn.consume_in_threads()

    return conn


def shutdown_rpc(conn):
    """Shutdown an RPC server

    This code lives similarly in neutron_lib.rpc.Service, but we cannot use it,
    as we need our own ThreadedConnection to be created and we cannot inherit
    from oslo_service.service.Service as this also uses eventlet.
    """
    # Try to shut the connection down, but if we get any sort of
    # errors, go ahead and ignore them.. as we're shutting down anyway
    try:
        conn.close()
    except Exception:  # nosec
        pass
