import ipaddress
import logging
import re
import urllib3

import pynetbox
import requests


LOG = logging.getLogger(__name__)


class ConfigException(Exception):
    pass


class ConfigSchemeException(ConfigException):
    pass


class ConfigGenerator:
    # FIXME: some of these shall be imported from networking-ccloud constants
    netbox_url = "https://netbox.global.cloud.sap"
    region = "qa-de-2"
    leaf_role = "evpn-leaf"
    spine_role = "evpn-spine"
    valid_vendors = {"arista", "cisco"}
    connection_roles = {"server"}

    netbox_switchgroup_tag = "cc-switchgroup"
    netbox_kv_tags = {netbox_switchgroup_tag}

    def __init__(self, region, verbose=False, verify_ssl=False):
        self.region = region
        self.verbose = verbose

        self.netbox = pynetbox.api(self.netbox_url)
        if not verify_ssl:
            urllib3.disable_warnings()
            self.netbox.http_session = requests.Session()
            self.netbox.http_session.verify = False

    def _get_kv_tags(self, entity):
        """Get a key-value dict with predefined keys from a netbox entity

        Some objects have tags, which we use as a key-value store in NetBox. Key and value
        are separated by a "-", but might themselves contain "-", so we remove the complete
        key + "-" and consider everything left a value.
        """
        kv_dict = {}
        for tag in entity.tags:
            for kv_tag in self.netbox_kv_tags:
                if tag.slug.startswith(f"{kv_tag}-"):
                    kv_dict[kv_tag] = tag.slug[len(kv_tag) + 1:]
        return kv_dict

    def calculate_ccloud_switch_number_resources(self, device, kv_tags, region_asn):
        """Calculate switch number resources specific to CCloud addressing schemes

        Should return loopback0, loopback1, loopback10, asn, role, switchgroup
        """
        # option a: parse from hostname
        # option b: get from kv_tags, if properly tagged

        # re matches qa-de-1-sw1234a-bb123
        m = re.match(r"(?P<region>\w{2}-\w{2}-\d)-sw(?P<az>\d)(?P<pod>\d)(?P<switchgroup>\d{2})(?P<leaf>[ab])"
                     r"(?:-(?P<role>\w+)",
                     device.name)
        if not m:
            raise ConfigSchemeException(f"Could not match '{device.name}' to CCloud hostname scheme "
                                        "(e.g. qa-de-1-sw1234a-bb123)")

        pod = int(m.group("pod"))
        switchgroup = int(m.group("switchgroup"))
        # leaf number is calculated by enumerating the leaf chars
        leaf = ord(m.group("leaf")) - ord("a") + 1
        az_no = int(m.group('az'))
        role = m.grou('role')
        switchgroup = None

        # handle role
        # FIXME: aci transit role missing
        if any(role.startswith(prefix) for prefix in ('np', 'ap', 'st', 'bb', 'bm')):
            switchgroup = role
            role = role[:2]
        elif role == 'bgw':
            switchgroup = f"bgw-{az_no}{pod}{switchgroup:02d}"
        else:
            raise ConfigSchemeException(f"Unknown / unhandled role {role} for device {device.name}")

        data = {
            'loopback0': ipaddress.ip_address(f"{az_no}.{pod}.{switchgroup}.{leaf}"),
            'loopback1': ipaddress.ip_address(f"{az_no}.{pod}.{switchgroup}.0"),
            'asn': f"{region_asn}.{az_no}{pod}{switchgroup:02d}",
            'role': role,
            'switchgroup': switchgroup,
        }
        return data

    def get_region_asn(self, region):
        sites = self.netbox.api.dcim.sites.filter(region=region)
        site_asns = {site.asn for site in sites if site.asn}
        if not site_asns:
            raise ConfigException(f"Region {region} has no ASN")
        if len(site_asns) > 1:
            raise ConfigException(f"Region {region} has multiple ASNs: {site_asns}")
        return site_asns[0]

    def get_switches(self, region_asn):
        switch_groups = {}
        switches = []

        leafs = self.netbox.dcim.devices.filter(region=self.region, role=self.leaf_role)
        for leaf in leafs:
            # FIXME: handle non-existent devicetype or manufacturer
            switch_name = leaf.name

            # vendor check!
            vendor = leaf.device_type.manufacturer.name.lower()
            if vendor not in self.valid_vendors:
                print(f"Warning: Device {switch_name} is of vendor {vendor}, "
                      "which is not supported by the driver/config generator")
                continue

            # find our switchgroup
            kv_tags = self._get_kv_tags(leaf)
            switch_group = kv_tags.get(self.netbox_switchgroup_tag)
            if not switch_group:
                print(f"Warning: Device {switch_name} is not part of any switchgroup, skipping it")
                continue

            switch_ports = []
            host_ports = {}
            ifaces = self.netbox.dcim.interfaces.filter(device_id=leaf.id)
            for iface in ifaces:
                # FIXME: ignore management, peerling (maybe), unconnected ports
                if iface.connected_endpoint is None:
                    continue

                far_device = iface.connected_endpoint.device
                if far_device.device_role.name.lower() not in self.connection_roles:
                    continue

                if self.verbose:
                    print(f"Device {switch_name} port {iface.name} is connected to "
                          f"device {far_device.name} port {iface.connected_endpoint.name} "
                          f"role {far_device.device_role.name}")

                host_ports.setdefault(far_device.name, []).append(iface.name)

            switch = {
                'name': switch_name,
                'ports': switch_ports,
                'hosts': host_ports,
                'vendor': vendor,
            }
            switch.update(self.calculate_ccloud_switch_number_resources(device, kv_tags, region_asn))
            switches.append(switch)
            # switch_groups.setdefault(switch_group, []).append(switch_name)

        # FIXME: check that no hostgroup has switches from two different switchgroups

        # return {
        #     'switch_groups': switch_groups,
        #     'switches': switches,
        # }
        return switches

    def generate_switch_config(self):
        region_asn = self.get_region_asn(self.region)
        config = {
            'switches': [],
            'switchgroups': [],
            'hostgroups': [],
        }

        switches = {}
        switchgroups = {}
        hostgroups = {}
        nb_switches = self.get_switches(region_asn)
        for nb_switch in nb_switches:
            switch = {}

        return config

    def do_sanity_check(self, config):
        # FIXME: after config has been created, load it with the normal driver verification stuff
        pass


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--region", required=True)
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    cfggen = ConfigGenerator(args.region, args.verbose)
    foo = cfggen.generate_switch_config()

    from pprint import pprint
    pprint(foo)


if __name__ == '__main__':
    main()
