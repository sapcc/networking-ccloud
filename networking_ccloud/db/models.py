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

from neutron_lib.db import model_base
from oslo_log import log as logging
import sqlalchemy as sa


LOG = logging.getLogger(__name__)


class CCNetworkInterconnects(model_base.BASEV2):
    """Mapping of BGWs and transits to networks and their AZs"""
    __tablename__ = 'cc_fabric_network_interconnects'

    device_type = sa.Column(sa.String(36), primary_key=True)
    network_id = sa.Column(sa.String(36), sa.ForeignKey('networks.id', ondelete='CASCADE'),
                           primary_key=True, index=True)
    availability_zone = sa.Column(sa.String(255), primary_key=True)
    host = sa.Column(sa.String(255))

    __table_args__ = (
        sa.Index('ix_device_type_network_id', 'device_type', 'network_id'),
    )
