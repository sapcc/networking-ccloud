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
import tempfile

from oslo_config import cfg
import yaml

from networking_ccloud.common.config import get_driver_config


def main():
    parser = argparse.ArgumentParser(
        description="This tool can be used to check if a config file for the driver would actually be "
                    "loadable by the driver. You also have the option to only check the yaml part of "
                    "the config separately."
    )
    parser.add_argument("-y", "--yaml-file", required=True)
    parser.add_argument("--uy", "--unwrap-yaml")
    parser.add_argument("--credentials-file")
    parser.add_argument("--uc", "--unwrap-credentials")

    args = parser.parse_args()

    # register necessary opts by importing our olso config
    from networking_ccloud.common.config import config_oslo  # noqa: F401

    with tempfile.NamedTemporaryFile(mode="w", delete=False) as conf_file, \
            tempfile.NamedTemporaryFile(mode="w", delete=False) as creds_file:

        if args.uy:
            with open(args.yaml_file) as f:
                y = yaml.safe_load(f.read())
            for key in args.uy.split("/"):
                if key not in y:
                    print(f"ERROR: missing key '{key}' in config, cannot unpack")
                    sys.exit(1)
                y = y[key]
            conf_file.write(yaml.dump(y))
            conf_file.close()
            args.yaml_file = conf_file.name
        cfg.CONF.set_override('driver_config_path', args.yaml_file, group='ml2_cc_fabric')

        if args.credentials_file:
            if args.uc:
                with open(args.credentials_file) as f:
                    y = yaml.safe_load(f.read())
                for key in args.uc.split("/"):
                    if key not in y:
                        print(f"ERROR: missing key '{key}' in config, cannot unpack")
                        sys.exit(1)
                    y = y[key]
                creds_file.write(yaml.dump(y))
                creds_file.close()
                args.credentials_file = creds_file.name
            cfg.CONF.set_override('driver_config_credentials_path', args.credentials_file, group='ml2_cc_fabric')

    # load yaml config
    drv_conf = get_driver_config(cached=False)
    print("OK - could load yaml config file")
    print(f"INFO - Config has {len(drv_conf.switchgroups)} switchgroups and "
          f"{len(drv_conf.hostgroups)} hostgroups")


if __name__ == '__main__':
    main()
