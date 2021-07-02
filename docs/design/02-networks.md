# OpenStack Networks
An OpenStack network is a L2 domain with a number of subnets. External networks can also have external gateways.

 * A network is external if `router:external` is set to true.
 * The VXLAN id for the top segment is chosen by openstack. The range is configured via `ml2_type_vxlan.vni_ranges`.

An OpenStack subnet represents a CIDR and can be associated with a subnet pool

 * A subnet is external if `router:external` is set to true.
 * An external subnet can have a gateway, which will be set up as an anycast gateway in the fabric

<details>
    <summary>Example of an internal network in OpenStack (json):</summary>
```json
{
  "admin_state_up": true,
  "availability_zone_hints": [],
  "availability_zones": [
    "qa-de-1a",
    "qa-de-1b"
  ],
  "description": "",
  "dns_domain": "",
  "id": "a7ec6c35-4e17-4e97-aa2b-0d93e56bb6c7",
  "ipv4_address_scope": null,
  "ipv6_address_scope": null,
  "is_default": null,
  "is_vlan_transparent": null,
  "mtu": 8950,
  "name": "cc-demo_private",
  "port_security_enabled": false,
  "project_id": "e9141fb24eee4b3e9f25ae69cda31132",
  "provider:network_type": null,
  "provider:physical_network": null,
  "provider:segmentation_id": null,
  "revision_number": 10421,
  "qos_policy_id": null,
  "router:external": false,
  "segments": [
    {
      "provider:network_type": "vxlan",
      "provider:physical_network": null,
      "provider:segmentation_id": 10091
    },
    {
      "provider:network_type": "vlan",
      "provider:physical_network": "cp090",
      "provider:segmentation_id": 2108
    },
    {
      "provider:network_type": "vlan",
      "provider:physical_network": "bb92",
      "provider:segmentation_id": 2046
    }
  ],
  "shared": false,
  "status": "ACTIVE",
  "subnets": [
    "0e1e5315-5b18-4af7-a63f-6369aadfbc19",
    "98697330-3e9e-4308-b351-eec5fcffe5b7"
  ],
  "tags": [],
}

```
</details>

<details>
    <summary>Example of an external network in OpenStack (json):</summary>
```json
{
  "admin_state_up": true,
  "availability_zone_hints": [],
  "availability_zones": [
    "qa-de-1a",
    "qa-de-1b"
  ],
  "description": "",
  "dns_domain": "",
  "id": "430991b3-da0d-41cb-ac54-d1d532841725",
  "ipv4_address_scope": "78dac149-7c96-4a38-b08d-8049f3abaf17",
  "ipv6_address_scope": null,
  "is_default": true,
  "is_vlan_transparent": null,
  "mtu": 8950,
  "name": "FloatingIP-external-monsoon3-03",
  "port_security_enabled": false,
  "project_id": "427b74d43e5144fc8536de33592ee78a",
  "provider:network_type": null,
  "provider:physical_network": null,
  "provider:segmentation_id": null,
  "qos_policy_id": null,
  "revision_number": 10421,
  "router:external": true,
  "segments": [
    {
      "provider:network_type": "vxlan",
      "provider:physical_network": null,
      "provider:segmentation_id": 10025
    },
    {
      "provider:network_type": "vlan",
      "provider:physical_network": "bb92",
      "provider:segmentation_id": 2412
    },
    {
      "provider:network_type": "vlan",
      "provider:physical_network": "cp090",
      "provider:segmentation_id": 2049
    }
  ],
  "shared": false,
  "status": "ACTIVE",
  "subnets": [
    "a5703f23-ffcb-4ca7-9dfe-ab9861d91bf5",
    "ac736737-1969-4e2c-9f6d-81b8b5278dd7",
    "c62a3c29-9fb0-4604-bf61-b8f8ff6c6777"
  ],
  "tags": [],
}
```
</details>

<detail>
    <summary>OpenStack external subnet
```json
{
  "allocation_pools": [
    {
      "start": "10.237.208.2",
      "end": "10.237.208.254"
    }
  ],
  "cidr": "10.237.208.0/24",
  "description": "",
  "dns_nameservers": [],
  "dns_publish_fixed_ip": null,
  "enable_dhcp": true,
  "gateway_ip": "10.237.208.1",
  "host_routes": [],
  "id": "a5703f23-ffcb-4ca7-9dfe-ab9861d91bf5",
  "ip_version": 4,
  "ipv6_address_mode": null,
  "ipv6_ra_mode": null,
  "name": "FloatingIP-sap-monsoon3-01-03",
  "network_id": "430991b3-da0d-41cb-ac54-d1d532841725",
  "prefix_length": null,
  "project_id": "427b74d43e5144fc8536de33592ee78a",
  "revision_number": 0,
  "segment_id": null,
  "service_types": [],
  "subnetpool_id": "e5d7bbe4-e6f3-4290-9822-54b5e97e3407",
  "tags": [],
}
```
</detail>
