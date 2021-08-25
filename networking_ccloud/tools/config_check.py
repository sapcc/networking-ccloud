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

import argparse
import sys

from oslo_config import cfg

from networking_ccloud.common.config import get_driver_config


def main():
    parser = argparse.ArgumentParser(
        description="This tool can be used to check if a config file for the driver would actually be "
                    "loadable by the driver. You also have the option to only check the yaml part of "
                    "the config separately."
    )
    parser.add_argument("-c", "--config-file")
    parser.add_argument("-y", "--yaml-file")

    args = parser.parse_args()

    if not (args.config_file or args.yaml_file):
        parser.error("Please specify either a config file or a yaml file to check")
    elif args.config_file and args.yaml_file:
        parser.error("Config file and yaml file checks via cli are mutually exclusive")

    if args.config_file:
        # register necessary opts by importing our olso config
        from networking_ccloud.common.config import config_oslo  # noqa: F401

        # use the normal driver config file loading facilities
        try:
            cfg.CONF(args=["--config-file", args.config_file])
        except cfg.Error as e:
            print(f"ERROR - Could not load oslo.config: {e}")
            sys.exit(1)

        print("OK - oslo.config could load driver config")

    # load yaml config (either via oslo config (args.yaml_file is None) or via path)
    drv_conf = get_driver_config(path=args.yaml_file)
    print("OK - could load yaml config file")
    print(f"INFO - Config has {len(drv_conf.switchgroups)} switchgroups and "
          f"{len(drv_conf.hostgroups)} hostgroups")


if __name__ == '__main__':
    main()
