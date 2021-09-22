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

from oslo_config import cfg
import yaml

from networking_ccloud.common.config.config_driver import DriverConfig
from networking_ccloud.common.config import config_oslo  # noqa: F401
_FABRIC_CONF = None


def _override_driver_config(driver_config):
    """Override driver config with an existing object

    This method is used by testing to inject the driver config without actually
    having a file.
    """
    global _FABRIC_CONF
    _FABRIC_CONF = driver_config


def get_driver_config(path=None, cached=True):
    """Get the driver config from a yaml file

    This method will load the config from a given path (or
    from ml2_cc_fabric.driver_config_path if no path is given) and return the
    parsed config. Subsequent calls ignore the path argument and return the
    previously parsed object from module state.
    """
    global _FABRIC_CONF
    if not cached or _FABRIC_CONF is None:
        if not path:
            path = cfg.CONF.ml2_cc_fabric.driver_config_path
            if path is None:
                raise ValueError("Missing value for ml2_cc_fabric.driver_config_path in config")

        # FIXME: error handling
        with open(path) as f:
            conf_data = yaml.safe_load(f)

        # FIXME: error handling
        _FABRIC_CONF = DriverConfig.parse_obj(conf_data)

    return _FABRIC_CONF
