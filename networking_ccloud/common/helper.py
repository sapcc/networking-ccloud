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

import json

from neutron_lib.api.definitions import portbindings as pb_api
from oslo_log import log as logging

from networking_ccloud.common import exceptions as cc_exc

LOG = logging.getLogger(__name__)


def get_binding_host_from_profile(profile, port_id):
    """Get a host from a binding_profile while handling broken data structures

    In case of baremetal the host is passed over via switch_info in the
    following data structure:

    {'local_link_information': [{'switch_info': 'host', ...}, ...]}

    As the binding_profile can come from anywhere, we want to make sure we
    don't fail on broken profiles. If the user tries to use multiple hosts an
    exception is thrown.
    """
    if not profile:
        return
    if isinstance(profile, str):
        try:
            profile = json.loads(profile)
        except json.decoder.JSONDecodeError as e:
            LOG.warning("Port %s has unloadable binding profile (%s), ignoring it", port_id, e)
            return
    if not isinstance(profile, dict):
        LOG.warning("Port %s has non-dict binding profile of type %s, ignoring it", port_id, type(profile))
        return
    if 'local_link_information' not in profile:
        return
    lli = profile['local_link_information']
    if not isinstance(lli, list):
        return

    hosts = set()
    for entry in lli:
        if not isinstance(entry, dict) or 'switch_info' not in entry:
            continue
        hosts.add(entry['switch_info'])

    if len(hosts) > 1:
        raise cc_exc.MultipleBindingHostsInBindingProfile(port_id=port_id, hosts=hosts)

    if hosts:
        return list(hosts)[0]


def get_binding_host_from_port(port):
    """Get usable binding host from a port

    Normally we use a port's binding:host_id, but we can't do this in case
    of baremetal. There, the binding:host_id is set to the node id, which
    is no help at all. We then need to look at the port's profile and
    determine if a host as been set there. This host then would take
    precedence.
    """
    profile_host = get_binding_host_from_profile(port.get(pb_api.PROFILE), port['id'])
    if profile_host:
        return profile_host
    return port[pb_api.HOST_ID]


def merge_segment_dicts(segments_a, segments_b):
    """Do an in-place merge of the second segments dict into the first segments dict"""
    for network_id, hosts in segments_b.items():
        segments_a.setdefault(network_id, {}).update(hosts)

    # we only return this for convenience, update is done in-place
    return segments_a
