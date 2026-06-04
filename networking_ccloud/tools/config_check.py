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
import contextlib
import os
import sys
import tempfile

from oslo_config import cfg
import yaml

from networking_ccloud.common.config import get_driver_config


def main():
    parser = argparse.ArgumentParser(
        description="Check if a driver config is loadable by the driver. The tool does the same validation "
                    "that is also done by the driver on startup."
    )
    parser.add_argument("-d", "--driver-config", required=True, help="Path to driver config yaml")
    parser.add_argument("--ud", "--unwrap-driver-config",
                        help="Unwrap config dict keys (separated with /), useful when reading config from a ConfigMap")
    parser.add_argument("--credentials-config", help="Path to driver credentials yaml")
    parser.add_argument("--uc", "--unwrap-credentials", help="Unwrap credentials dict keys (separated with /)")

    args = parser.parse_args()

    def _traverse_dict(data, path, item_name):
        for key in path.split("/"):
            if not isinstance(data, dict):
                print(f"ERROR: found non-dict object in {item_name} path, cannot unpack")
                sys.exit(1)
            if key not in data:
                print(f"ERROR: missing key '{key}' in {item_name}, cannot unpack")
                sys.exit(1)
            data = data[key]
        return data

    with tempfile.NamedTemporaryFile(mode="w", delete=False) as conf_file, \
            tempfile.NamedTemporaryFile(mode="w", delete=False) as creds_file:

        # TODO(seba): on py3.12 replace this try-finally with delete_on_close
        try:
            # driver config
            if args.ud:
                with open(args.driver_config) as f:
                    y = yaml.safe_load(f)
                y = _traverse_dict(y, args.ud, "driver config")
                yaml.dump(y, conf_file)
                conf_file.close()
                args.driver_config = conf_file.name
            cfg.CONF.set_override('driver_config_path', args.driver_config, group='ml2_cc_fabric')

            # credentials config
            if args.credentials_config:
                if args.uc:
                    with open(args.credentials_config) as f:
                        y = yaml.safe_load(f)
                    y = _traverse_dict(y, args.uc, "driver credentials")
                    yaml.dump(y, creds_file)
                    creds_file.close()
                    args.credentials_config = creds_file.name
                cfg.CONF.set_override('driver_config_credentials_path', args.credentials_config, group='ml2_cc_fabric')

            # load driver config
            try:
                drv_conf = get_driver_config(cached=False)
            except Exception as e:
                print(f"ERROR - could not load driver config: {type(e)} {e}")
                sys.exit(1)

            print("OK - driver config is valid")
            print(f"INFO - driver config has {len(drv_conf.switchgroups)} switchgroups and "
                  f"{len(drv_conf.hostgroups)} hostgroups")
        finally:
            with contextlib.suppress(Exception):
                os.remove(conf_file.name)
            with contextlib.suppress(Exception):
                os.remove(creds_file.name)


if __name__ == '__main__':
    main()
