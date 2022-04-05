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

"""Initial

Revision ID: 326d8c70ff8b
Revises: None
Create Date: 2022-02-17 14:11:08.359308

"""

from neutron.db.migration import cli


# revision identifiers, used by Alembic.
revision = '326d8c70ff8b'
down_revision = '511ca4e2e1dc'
branch_labels = (cli.CONTRACT_BRANCH,)


def upgrade():
    pass
