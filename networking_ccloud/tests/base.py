# -*- coding: utf-8 -*-
#
# Copyright 2021 SAP SE
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import json

from neutron.common import config
from neutron.plugins.ml2 import models as ml2_models
from neutron_lib import context
from oslo_config import cfg
from oslotest import base


class TestCase(base.BaseTestCase):
    """Test case base class for all unit tests."""

    def setUp(self):
        super().setUp()

        # configure debug logging (see also neutron.tests.base setup_test_logging())
        cfg.CONF.set_override('debug', True)
        config.setup_logging()


class PortBindingHelper():
    def _make_port_with_binding(self, segments, host, **kwargs):
        kwargs['binding:host_id'] = host
        profile = kwargs.pop('profile', None)
        if profile:
            profile = json.dumps(profile)
        vif_type = kwargs.pop('vif_type', 'cc-test-vif')
        kwargs.setdefault('device_owner', 'compute:None')
        kwargs.setdefault('device_id', '1234')
        port = self._make_port('json', segments[0][0]['network_id'], host=host, **kwargs)['port']
        ctx = context.get_admin_context()
        with ctx.session.begin():
            pbinding = ml2_models.PortBinding(port_id=port['id'], host=host, profile=profile, vif_type=vif_type)
            ctx.session.add(pbinding)

            for level, (segment, driver) in enumerate(segments):
                pbl = ml2_models.PortBindingLevel(port_id=port['id'], host=host, level=level,
                                                  driver=driver, segment_id=segment['id'])
                ctx.session.add(pbl)
        return port
