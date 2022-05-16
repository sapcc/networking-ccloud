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

from neutron_lib import exceptions as n_exc


class MultipleBindingHostsInBindingProfile(n_exc.NeutronException):
    """An exception indicating multiple hosts found in binding profile"""
    message = "Port %(port_id)s has multiple hosts in binding profile; refusing to work with it! Hosts were: %(hosts)s"


class UnsupportedHandoverMode(n_exc.NeutronException):
    """Raised when a hostgroup is configured with an unsupported handover mode"""
    message = "Hostgroup %(hostgroup_name)s has unsupported handover mode %(handover_mode)s"


class MissingPhysnetsInNeutronConfig(n_exc.NeutronException):
    """Raised when yaml driver config is not in sync with neutron segmentation config"""
    message = ("Not all physical networks defined in the driver config have a vlan pool assigned in "
               "ml2_type_vlan.network_vlan_ranges. Missing physical networks are: %(missing_physnets)s")


class SpecialDevicesBindingProhibited(n_exc.BadRequest):
    """Raised when a user tries to bind a transit or BGW"""
    message = ("Binding special devices like transit or BGWs is prohibited (port %(port_id)s host %(host)s")


class OnlyOneAZHintAllowed(n_exc.BadRequest):
    message = "Only one availability zone hint allowed per object"


class HostNetworkAZAffinityError(n_exc.BadRequest):
    message = "Host %(host)s resides in AZ %(hostgroup_az)s, network requires AZ %(network_az)s"


class SwitchConnectionError(Exception):
    pass
