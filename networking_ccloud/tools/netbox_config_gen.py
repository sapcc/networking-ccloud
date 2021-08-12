import ipaddress
from itertools import groupby
import logging
from operator import itemgetter
import re
import urllib3

import pynetbox
import requests

# FIXME: make this a module import once this is a proper module
import conftest as conf


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

    def __init__(self, region, args, verbose=False, verify_ssl=False):
        self.region = region
        self.args = args
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
        m = re.match(r"^(?P<region>\w{2}-\w{2}-\d)-sw(?P<az>\d)(?P<pod>\d)(?P<switchgroup>\d{2})(?P<leaf>[ab])"
                     r"(?:-(?P<role>[a-z0-9-]+))$",
                     device.name)
        if not m:
            raise ConfigSchemeException(f"Could not match '{device.name}' to CCloud hostname scheme "
                                        "(e.g. qa-de-1-sw1234a-bb123)")

        pod = int(m.group("pod"))
        switchgroup = int(m.group("switchgroup"))
        # leaf number is calculated by enumerating the leaf chars
        leaf = ord(m.group("leaf")) - ord("a") + 1
        az_no = int(m.group('az'))
        role = m.group('role')
        switchgroup_name = None

        # handle role
        # FIXME: aci transit role missing
        if any(role.startswith(prefix) for prefix in ('np', 'ap', 'st', 'bb', 'bm')):
            switchgroup_name = role
            role = role[:2]
            if role == 'bb':
                role = 'v'
            role += "pod"
        elif role == 'bgw':
            switchgroup_name = f"bgw-{az_no}{pod}{switchgroup:02d}"
        else:
            raise ConfigSchemeException(f"Unknown / unhandled role {role} for device {device.name}")

        # use nb primary address for now, later this is probably going to be loopback10
        if not device.primary_ip:
            raise ConfigSchemeException(f"Device {device.name} does not have a usable primary address")
        host_ip = device.primary_ip.address.split("/")[0]

        data = {
            'loopback0': ipaddress.ip_address(f"{az_no}.{pod}.{switchgroup}.{leaf}"),
            'loopback1': ipaddress.ip_address(f"{az_no}.{pod}.{switchgroup}.0"),
            'asn': f"{region_asn}.{az_no}{pod}{switchgroup:02d}",
            'role': role,
            'switchgroup': switchgroup_name,
            'host': host_ip,
        }
        return data

    def get_region_asn(self, region):
        sites = self.netbox.dcim.sites.filter(region=region)
        site_asns = {site.asn for site in sites if site.asn}
        if not site_asns:
            raise ConfigException(f"Region {region} has no ASN")
        if len(site_asns) > 1:
            raise ConfigException(f"Region {region} has multiple ASNs: {site_asns}")
        return site_asns.pop()

    def get_netbox_switches(self, region):
        region_asn = self.get_region_asn(region)
        switches = []

        leafs = self.netbox.dcim.devices.filter(region=region, role=self.leaf_role)
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
                # FIXME: ignore management, peerlink (maybe), unconnected ports
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
                'az': leaf.site.name,
            }
            switch.update(self.calculate_ccloud_switch_number_resources(leaf, kv_tags, region_asn))
            switches.append(switch)
            # switch_groups.setdefault(switch_group, []).append(switch_name)

        # FIXME: check that no hostgroup has switches from two different switchgroups

        return switches

    def generate_switch_config(self):
        config = {
            'switches': [],
            'switchgroups': [],
            'hostgroups': [],
        }

        nb_switches = self.get_netbox_switches(self.region)

        def _get_single(item_set, item_name, switchgroup):
            if len(item_set) > 1:
                raise ConfigException(f"Inconsistent {item_name} found for switchgroup {switchgroup}: {item_set}")
            return item_set.pop()

        from pprint import pprint
        pprint(nb_switches)

        # build switchgroups
        switchgroups = []
        for groupname, nb_switches in groupby(nb_switches, key=itemgetter('switchgroup')):
            switches = []
            az = set()
            role = set()
            loopback1 = set()
            asn = set()
            for nb_switch in sorted(nb_switches, key=itemgetter('name')):
                az.add(nb_switch['az'])
                role.add(nb_switch['role'])
                loopback1.add(nb_switch['loopback1'])
                asn.add(nb_switch['asn'])
                switch = conf.Switch(name=nb_switch['name'], host=nb_switch['host'],
                                     ip_loopback0=nb_switch['loopback0'], vendor=nb_switch['vendor'],
                                     user=self.args.switch_user, password=self.args.switch_password)

                switches.append(switch)
            az = _get_single(az, "AZ", groupname)
            role = _get_single(role, "role", groupname)
            loopback1 = _get_single(loopback1, "loopback1", groupname)
            asn = _get_single(asn, "asn", groupname)
            switchgroup = conf.SwitchGroup(name=groupname, members=switches, availability_zone=az, role=role,
                                           ip_loopback1=loopback1, asn=asn)
            switchgroups.append(switchgroup)

        # build hostgroups
        hostgroups = []

        # build top config object
        config = conf.DriverConfig(switchgroups=switchgroups, hostgroups=hostgroups)

        return config

    def do_sanity_check(self, config):
        # FIXME: after config has been created, load it with the normal driver verification stuff
        pass


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--region", required=True)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-u", "--switch-user", help="Default switch user", required=True)
    parser.add_argument("-p", "--switch-password", help="Default switch password", required=True)

    args = parser.parse_args()

    cfggen = ConfigGenerator(args.region, args, args.verbose)
    foo = cfggen.generate_switch_config()

    from pprint import pprint
    pprint(foo)


if __name__ == '__main__':
    main()
