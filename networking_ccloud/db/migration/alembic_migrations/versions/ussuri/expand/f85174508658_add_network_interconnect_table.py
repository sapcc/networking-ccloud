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
#

"""Add network interconnect mapping table for transits and BGWs

Revision ID: f85174508658
Revises: d5c2a509b5d6
Create Date: 2022-03-14 18:28:47.409701

"""

# revision identifiers, used by Alembic.
revision = 'f85174508658'
down_revision = 'd5c2a509b5d6'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'cc_fabric_network_interconnects',
        sa.Column('device_type', sa.String(length=36), nullable=False),
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('availability_zone', sa.String(length=255), nullable=False),
        sa.Column('host', sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('device_type', 'network_id', 'availability_zone')
    )
    op.create_index(op.f('ix_cc_fabric_network_interconnects_network_id'),
                    'cc_fabric_network_interconnects', ['network_id'], unique=False)
    op.create_index('ix_device_type_network_id',
                    'cc_fabric_network_interconnects', ['device_type', 'network_id'], unique=False)
