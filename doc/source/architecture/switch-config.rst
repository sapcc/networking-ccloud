Device Config
~~~~~~~~~~~~~
This document describes the mapping of Openstack Neutron objects to device configuration including limits and supported feature combinations.

*********
Network
*********
A Neutron Network is the basis for all other operations it is an assumed L2 broadcast domain.

Overview
########
This driver implements Neutron networks by way of establishing a 1:1 mapping between a Neutron Network and a VXLAN-EVPN VNI.
The VNI ID is managed by the Neutron server and is recorded as top level segment in the neutron segments table for a specific network.The driver will on demand create sub-segments (hierarchical port binding) whenever a specific network is required on a EVPN leaf switch or group of leaf switches. Those sub segments include a segmentation ID of type VLAN which is the switch/group local VLAN ID which will be used for VNI to VLAN mapping by the driver.

Single AZ
---------
Single AZ networks are only configured within one EVPN domain. Inter-AZ traffic for single AZ
networks is routed L3 only.

Multi AZ
--------
Multi AZ networks span over multiple EVPN Domains, the network is extended between EVPN domains 
using EVPN border gateway or EVPN multi site functionality. The driver will configure ALL 
border gateways when the first port is going through ml2 port binding for a given network 
and will remove the configuration when the last port in the network is removed.

Workflow
--------
All fabric configuration is triggered by ml2 port binding requests, depending on the 
network settings the below workflow is triggered to determine the config and scope 
that is required to extend the neutron network to the devices.

.. figure:: figure/network_provisioning_flow.svg
    :width: 400px
    :align: center
    :figclass: align-center

Legacy Fabric Integration
#########################
The driver supports the integration with a legacy network fabric managed by 
another neutron driver in a multi-az environment.

Legacy driver coordination
--------------------------
The transit (a L2 trunk between fabrics) is used to connect the fabric to 
another network environment managed by a different ml2
top level driver. The legacy driver and this driver (networking-ccloud) both 
share responsibility for the top segment.
For this to work they need to be interconnected. This means that whenever
an OpenStack network should be present both on legacy and networking-ccloud side
it requires a transit segment between these two fabrics. Those transit points 
have to be coordinated between the two drivers (VLAN allocation, etc.).

Other drivers will have to be notified of this change, options are:
 * having an own signal in bind_port
 * use ml2 `(create|update|delete)_port_postcommit` hooks

In config each Transit will have a list of AZs associated with it
that it can service. Whenever a network is potentially present in 
both environments the driver will pick a transit point in each az 
(multiple transits per AZ are allowed and will be scheduled least-used)
which has transits defined. 

The guarantee of loop free forwarding is outside of the scope of the driver
and is guaranteed to be solved in the underlying base configuration.

Legacy fabric interconnection
-----------------------------

The transit is done by having switch pairs connected back-to-back, one on
each side and having the drivers coordinate on the VLANs used on both sides.
Networking-ccloud will create the necessary segment, as it is on top of the hierarchy.
If more networks need to be transited than a single switch pair can service 
and there are more than one transit pair available in an AZ the driver
will schedule to the least used pair.

The driver is not responsible for loop avoidance or migration of flows between fabric interconnections, this is expected to be handled via the static non-driver controlled configuration.
The following topology variations need to be supported, for below scenarios it is expected that the network is already in use in legacy.

Single AZ
---------
There exists only a single AZ and both fabrics are interconnected with one or more transit pairs.

.. figure:: figure/legacy_fabric_type_single_az.svg
    :width: 300px
    :align: center
    :figclass: align-center

* Single AZ Network a
   #. Additional segment for L2 trunk EVPN<->Legacy in AZa is added.

Dual AZ with Dual Legacy AZ
---------------------------
There are two AZs and both have a legacy and a EVPN deployment.

.. figure:: figure/legacy_fabric_type_dual_az.svg
    :width: 300px
    :align: center
    :figclass: align-center


* Single AZ Network a or b
   #. Additional segment for L2 trunk EVPN<->Legacy in network local AZ

* Multi AZ Network
   #. Additional segment for L2 trunk EVPN<->Legacy in ALL AZs
   #. Additional segment for BGW in ALL AZs

Dual AZ with Single Legacy AZ
-----------------------------
There are two AZs and only one AZ has a legacy and a EVPN deployment.

.. figure:: figure/legacy_fabric_type_dual_az_evpn.svg
    :width: 300px
    :align: center
    :figclass: align-center

* Single AZ Network a
   #. Additional segment for L2 trunk EVPN<->Legacy in network local AZ

* Single AZ Network b
   #. No additional action required

* Multi AZ Network
   #. Additional segment for L2 trunk EVPN<->Legacy in AZ a
   #. Additional segment for BGW in ALL AZs

Multi AZ with Multi Legacy AZ
-----------------------------

.. figure:: figure/legacy_fabric_type_multi_az.svg
    :width: 450px
    :align: center
    :figclass: align-center

* Single AZ Network
   #. Additional segment for L2 trunk EVPN<->Legacy in network local AZ

* Multi AZ Network
   #. Additional segment for L2 trunk EVPN<->Legacy in ALL AZs
   #. Additional segment for BGW in ALL AZs

Multi AZ with Dual Legacy AZ
----------------------------

.. figure:: figure/legacy_fabric_type_multi_az_evpn.svg
    :width: 450px
    :align: center
    :figclass: align-center

* Single AZ Network a/b
   #. Additional segment for L2 trunk EVPN<->Legacy in network local AZ

* Single AZ Network c
   #. No additional action required

* Multi AZ Network
   #. Additional segment for L2 trunk EVPN<->Legacy in AZa AND AZb
   #. Additional segment for BGW in ALL AZs

Sample Driver Configuration
###########################
::

   [ml2_cc_fabric]
   regional_l3 = false
   az_l3 = qa-de-1d

::

   global:
      asn_region: 65130
      infra_network_default_vrf: CC-MGMT
      vrfs:
        CC-MGMT:
          rd: 900

   hostgroups:
   - binding_hosts:
     - node001-bb301
     members:
     - name: Ethernet1/1
       switch: qa-de-3-sw1103a-bb301
     - name: Ethernet1/1
       switch: qa-de-3-sw1103b-bb301
   - binding_hosts:
     - node002-bb301
     members:
     - name: Ethernet2/1
       switch: qa-de-3-sw1103a-bb301
     - name: Ethernet2/1
       switch: qa-de-3-sw1103b-bb301
     - name: Port-Channel 201
       switch: qa-de-3-sw1103a-bb301
       lacp: true
       members: [Ethernet3/1]
     - name: Port-Channel 201
       switch: qa-de-3-sw1103b-bb301
       lacp: true
       members: [Ethernet3/1]
   - binding_hosts:
     - nova-compute-bb301
     members:
     - node001-bb301
     - node002-bb301
     infra_networks:
     - vni: 10301100
       vlan: 100
       vrf: CC-MGMT
       untagged: true
       networks: [ 10.246.100.1/24 ]
       dhcp_relays: [147.204.1.45, 10.247.3.122]
     - vni: 10301101
       vlan: 101
     metagroup: true

   switchgroups:
   - asn: '65130.1103'
     availability_zone: qa-de-1a
     members:
     - bgp_source_ip: 1.1.03.1
       host: 10.114.0.203
       name: qa-de-1-sw1103a-bb301
       password: nope
       user: admin2
       platform: arista-eos
     - bgp_source_ip: 1.1.03.2
       host: 10.114.0.204
       name: qa-de-3-sw1103b-bb301
       password: api-password
       user: api-user
       platform: arista-eos
     name: bb301
     role: vpod
     vtep_ip: 1.1.03.0

Sample Network Definition
#########################

::

   {
     "admin_state_up": true,
     "availability_zones": [
       "qa-de-1a",
       "qa-de-1b",
       "qa-de-1d"
     ],
     "id": "aeec9fd4-30f7-4398-8554-34acb36b7712",
     "ipv4_address_scope": "24908a2d-55e8-4c03-87a9-e1493cd0d995",
     "mtu": 8950,
     "name": "FloatingIP-external-sfh03-eude1",
     "project_id": "07ed7aa018584972b40d94697b70a37b",
     "router:external": true,
     "segments": [
       {
         "provider:network_type": "vxlan",
         "provider:physical_network": null,
         "provider:segmentation_id": 10394
       },
       {
         "provider:network_type": "vlan",
         "provider:physical_network": "bb301",
         "provider:segmentation_id": 3150
       },
       {
         "provider:network_type": "vlan",
         "provider:physical_network": "transit-leaf",
         "provider:segmentation_id": 2300
       }
       {
         "provider:network_type": "vlan",
         "provider:physical_network": "bgw",
         "provider:segmentation_id": 2340
       }
     ],
     "status": "ACTIVE",
     "subnets": [
       "14b7b745-8d5d-4667-a3e3-2be0facbb23d",
       "72f96182-d93d-4aa7-a987-edb315875c9e",
       "bbe371ae-341b-4f86-931a-e9c808cb312e"
     ],
   }

Single AZ Network
-----------------
Networks with a single AZ are identified by having a availability_zones list of size 1.
Networks with multiple hints are not supported by the driver and will be rejected.

::

   {
     "admin_state_up": true,
     "availability_zone_hints": [
       "qa-de-1a"
     ],
     "availability_zones": [
       "qa-de-1a"
     ],
     "id": "fce02a86-525c-49c9-a6cd-bf472881a83f",
     "ipv4_address_scope": "24908a2d-55e8-4c03-87a9-e1493cd0d995",
     "mtu": 8950,
     "name": "FloatingIP-A",
     "project_id": "07ed7aa018584972b40d94697b70a37b",
     "router:external": true,
     "segments": [
       {
         "provider:network_type": "vxlan",
         "provider:physical_network": null,
         "provider:segmentation_id": 10400
       },
       {
         "provider:network_type": "vlan",
         "provider:physical_network": "bb301",
         "provider:segmentation_id": 3200
       }
     ],
     "status": "ACTIVE",
     "subnets": [
       "f77d7403-c46a-42d0-a20b-d104b8bc203f",
     ],
   }
       {
        "availability_zone_hints": [
          "qa-de-1a",
        ],
        "availability_zones": [
          "qa-de-1a",
        ],
       }

Multi AZ Network
-----------------
Networks with multiple AZs are identified by having a availability_zones list of size N,
meaning all possible AZs of the region. Networks only spanning some but not all AZs are not supported by the driver.
Regional networks are expected to not have an AZ hint set.

::

    {
     "availability_zone_hints": [
     ],
     "availability_zones": [
       "qa-de-1a",
       "qa-de-1b",
       "qa-de-1d"
     ],
    }

On Device configuration
#######################

aPOD/vPOD/stPOD/netPOD/bPOD/Transit leafs
-----------------------------------------

**EOS**:
::

   interface Vxlan1
      vxlan vlan 3150 vni 10394

   vlan 3150
      name aeec9fd4-30f7-4398-8554-34acb36b7712/bb301

   router bgp 65130.1112
     vlan 3150
         rd 1112:10394
         route-target export 1:10394
         route-target import 1:10394
         redistribute learned
         redistribute static

**NX-OS**:
::

   interface nve1
      member vni 10394
         ingress-replication protocol bgp
         suppress-arp

   vlan 2420
      name aeec9fd4-30f7-4398-8554-34acb36b7712/bb301
      vn-segment 10394

   router bgp 65130.1103
      evpn
         vni 10394 l2
            rd 1103:10394
            route-target export 1:10394
            route-target import 1:10394

Border Gateway
--------------
Only applicable for regional networks.

**EOS**:
::

   interface Vxlan1
      vxlan vlan 2340 vni 10394

   vlan 2340
      name aeec9fd4-30f7-4398-8554-34acb36b7712/bgw

   router bgp 65130.1103
      vlan 2340
         rd evpn domain all 65130.1103:10394
         route-target export 65130:999
         route-target export 65130.1:10394
         route-target import 65130.1:10394
         route-target import export evpn domain remote 65130:10394
         redistribute learned

**NX-OS**:

*********
Subnet
*********
There exists RT convention to describe the span of a subnet (regional vs AZ local) and
to tag a prefix as a supernet that should be announced towards upstream routers:

.. list-table:: RT and Community Schema
   :header-rows: 1

   * - 
     - Type
     - AZa
     - AZb
     - AZc
     - AZd
   * - CC-CLOUDXX Regional
     - Ext RT
     - $REGION_ASN:1XX
     - $REGION_ASN:1XX
     - $REGION_ASN:1XX
     - $REGION_ASN:1XX
   * - CC-CLOUDXX perAZ
     - Ext RT
     - $REGION_ASN:11XX
     - $REGION_ASN:21XX
     - $REGION_ASN:31XX
     - $REGION_ASN:41XX
   * - Aggregates to Core
     - Std Community
     - $REGION_ASN.1
     - $REGION_ASN.1
     - $REGION_ASN.1
     - $REGION_ASN.1
  
External Network
################

Sample Driver Configuration
---------------------------

::

   [address-scope:hcp03-public]
   export_rt_suffix = 102
   import_rt_suffix = 102
   vrf = cc-cloud02

Sample Subnet Definition
------------------------

::

   ######### Example External Address Scope
   {
     "id": "f2fd984c-45b1-4465-9f99-e72f86b896fa",
     "name": "hcp03-public",
   }
   ######### Example Subnet Pool Regional
   {
     "address_scope_id": "f2fd984c-45b1-4465-9f99-e72f86b896fa",
     "id": "e6df3de0-16dd-46e3-850f-5418fd6dd820",
     "prefixes": [
       "10.47.10.0/24",
       "10.47.8.0/24"
     ],
   }
   ######### Example Subnet Pool AZa
   {
     "address_scope_id": "f2fd984c-45b1-4465-9f99-e72f86b896fa",
     "id": "fbc4b555-4266-46a0-916b-3863c649223a",
     "prefixes": [
       "10.47.20.0/24"
     ],
   }
   ######### Example External Networks
   {
     "id": "aeec9fd4-30f7-4398-8554-34acb36b7712",
     "ipv4_address_scope": "24908a2d-55e8-4c03-87a9-e1493cd0d995",
     "router:external": true,
     "availability_zones": [
       "qa-de-1a",
       "qa-de-1b",
       "qa-de-1d"
     ],
   }
   {
     "id": "fce02a86-525c-49c9-a6cd-bf472881a83f",
     "ipv4_address_scope": "24908a2d-55e8-4c03-87a9-e1493cd0d995",
     "router:external": true,
     "availability_zones": [
       "qa-de-1a"
     ],
   }
   ######### Subnets
   {
     "cidr": "10.47.8.192/27",
     "gateway_ip": "10.47.8.193",
     "host_routes": [],
     "id": "bbe371ae-341b-4f86-931a-e9c808cb312e",
     "ip_version": 4,
     "name": "FloatingIP-sap-sfh03-eude1-01",
     "network_id": "aeec9fd4-30f7-4398-8554-34acb36b7712",
     "subnetpool_id": "e8556528-01e6-4ccd-9286-0145ac7a75f4",
   }
   {
     "cidr": "10.47.10.0/24",
     "gateway_ip": "10.47.10.1",
     "host_routes": [],
     "id": "14b7b745-8d5d-4667-a3e3-2be0facbb23d",
     "ip_version": 4,
     "name": "FloatingIP-Regional",
     "network_id": "aeec9fd4-30f7-4398-8554-34acb36b7712",
     "subnetpool_id": "e8556528-01e6-4ccd-9286-0145ac7a75f4",
   }
   {
     "cidr": "10.47.20.0/25",
     "gateway_ip": "10.47.20.1",
     "host_routes": [],
     "id": "f77d7403-c46a-42d0-a20b-d104b8bc203f",
     "ip_version": 4,
     "name": "FloatingIP-AZa",
     "network_id": "fce02a86-525c-49c9-a6cd-bf472881a83f",
     "subnetpool_id": "fbc4b555-4266-46a0-916b-3863c649223a",
   }

On Device configuration
-----------------------
All examples use CC-CLOUD02 and availability-zone A as examples.

For the prefixes that need to be redistributed into BGP there are the following combinations:

.. list-table:: BGP prefix properties
   :widths: 10 10 40 40
   :header-rows: 1

   * - az-local
     - is externally announced (CIDR in address scope)
     - config EOS
     - config NXOS
 
   * - False
     - False
     - * entry in `PL-CC-CLOUD02`
       * :code:`aggregate-address <supernet> attribute-map RM-CC-CLOUD02-AGGREGATE`
     - * :code:`network <prefix> route-map RM-CC-CLOUD02``
       * :code:`aggregate-address  <supernet>  attribute-map RM-CC-CLOUD02-AGGREGATE`
 
   * - True
     - False
     - * entry in `PL-CC-CLOUD02-A`
       * :code:`aggregate-address <supernet> attribute-map RM-CC-CLOUD02-A-AGGREGATE`
     - * :code:`network <prefix> route-map RM-CC-CLOUD02-A`
       * :code:`aggregate-address  <supernet>  attribute-map RM-CC-CLOUD02-A-AGGREGATE`
 
   * - False
     - True
     - * entry in `PL-CC-CLOUD02-EXTERNAL`
     - * :code:`network <prefix> route-map RM-CC-CLOUD02-AGGREGATE`
 
   * - True
     - True
     - * entry in `PL-CC-CLOUD02-A-EXTERNAL`
     - * :code:`network <prefix> route-map RM-CC-CLOUD02-AGGREGATE`
  
**EOS**:

We assume the following L3 related config to be preconfigured on each device, example for AZ A, regional ASN 65130, VRF CC-CLOUD02:

::

  vrf instance CC-CLOUD02

  ip routing vrf CC-CLOUD02

  route-map RM-CC-CLOUD02-REDIST permit 10
    match ip address prefix-list PL-CC-CLOUD02
    set community 65130:102
    set extcommunity rt 65130:102
  route-map RM-CC-CLOUD02-REDIST permit 20
    match ip address prefix-list PL-CC-CLOUD02-A
    set community 65130:1102
    set extcommunity rt 65130:1102
  route-map RM-CC-CLOUD02-REDIST permit 30
    match ip address prefix-list PL-CC-CLOUD02-EXTERNAL
    set community 65130:1 65130:102
    set extcommunity rt 65130:102
  route-map RM-CC-CLOUD02-REDIST permit 40
    match ip address prefix-list PL-CC-CLOUD02-A-EXTERNAL
    set community 65130:1 65130:1102
    set extcommunity rt 65130:1102

  route-map RM-CC-CLOUD02-AGGREGATE permit 10
    set community 65130:1 65130:102
    set extcommunity rt 65130:102

  route-map RM-CC-CLOUD02-A-AGGREGATE permit 10
    set community 65130:1 65130:1102
    set extcommunity rt 65130:1102

  # These prefix lists must be preconfigured, otherwise Octa fails to
  # build a valid config tree
  ip prefix-list PL-CC-CLOUD02
  ip prefix-list PL-CC-CLOUD02-A
  ip prefix-list PL-CC-CLOUD02-EXTERNAL
  ip prefix-list PL-CC-CLOUD02-A-EXTERNAL

  interface Vxlan1
    vxlan vrf CC-CLOUD02 vni 102

  router bgp 65130.1103
    vrf CC-CLOUD02
      rd 65130.1103:102
      route-target export evpn 65130:1102
      route-target import evpn 65130:102
      route-target import evpn 65130:1102
      route-target import evpn 65130:2102
      route-target import evpn 65130:4102
      redistribute connected route-map RM-CC-CLOUD02-REDIST
      redistribute static route-map RM-CC-CLOUD02-REDIST
  
  # Octa crashes when `redistribute static` is configured but no static route is present
  # Let us configure a dummy route from the zeroconf range to hackaround that problem
  ip route vrf CC-CLOUD02 169.254.255.255 255.255.255.255 null0   


Driver controlled configuration:

::

  # The driver assumes full control over these prefix-lists
  # any prefix unknown to the driver will be removed.

  ip prefix-list PL-CC-CLOUD02
    seq 10 permit 10.47.8.192/27

  ip prefix-list PL-CC-CLOUD02-A
    seq 10 permit 10.47.20.0/25

  ip prefix-list PL-CC-CLOUD02-EXTERNAL
    seq 10 permit 10.47.10.0/24

  ip prefix-list PL-CC-CLOUD02-A-EXTERNAL

  interface Vlan3150
    description aeec9fd4-30f7-4398-8554-34acb36b7712
    vrf CC-CLOUD02
    ip address virtual 10.47.8.193/27
    ip address virtual 10.47.10.1/24 secondary

  interface Vlan3200
    description fce02a86-525c-49c9-a6cd-bf472881a83f
    vrf CC-CLOUD02
    ip address virtual 10.47.20.1/25

  router bgp 65130.1103
    vrf CC-CLOUD02
      # The driver assumes full control over aggregate address statements,
      # that have an attribute-map/route-map associated that complies with
      # f'RM-CC-{VRF}-AGGREGATE' or f'RM-CC-{VRF}-{AZ}-AGGREGATE'
      # any aggregate statement not known to the driver will be removed
      aggregate-address 10.47.8.0/24 attribute-map RM-CC-CLOUD02-A-AGGREGATE
      aggregate-address 10.47.20.0/24 attribute-map RM-CC-CLOUD02-AGGREGATE



**NX-OS**:
::

   route-map RM-CC-CLOUD02
      set extcommunity rt 65130:102

   route-map RM-CC-CLOUD02-AGGREGATE
      set community 65130:1
      set extcommunity rt 65130:102

   route-map RM-CC-CLOUD02-A

   route-map RM-CC-CLOUD02-A-AGGREGATE
      set community 65130:1

   interface Vlan 3150
      description aeec9fd4-30f7-4398-8554-34acb36b7712
      no shutdown
      vrf member CC-CLOUD02
      ip forward
      ip address 10.47.8.193/27
      ip address 10.47.10.1/24 secondary

   interface Vlan 3200
      description  fce02a86-525c-49c9-a6cd-bf472881a83f
      no shutdown
      vrf member CC-CLOUD02
      ip forward
      ip address 10.47.20.1/25

   interface nve1
      member vni 102 associate-vrf

   vrf context CC-CLOUD02
      vni 102
      rd 65130.1103:102
      address-family ipv4 unicast
         route-target export 65130:1102
         route-target export 65130:1102 evpn
         route-target import 65130:102
         route-target import 65130:102 evpn
         route-target import 65130:1102
         route-target import 65130:1102 evpn
         route-target import 65130:2102
         route-target import 65130:2102 evpn
         route-target import 65130:4102
         route-target import 65130:4102 evpn

   router bgp 65130.1103
      vrf CC-CLOUD02
         address-family ipv4 unicast
            aggregate-address 10.47.8.0/24 attribute-map RM-CC-CLOUD02-AGGREGATE
            aggregate-address 10.47.20.0/24 attribute-map RM-CC-CLOUD02-A-AGGREGATE
            network 10.47.8.192/27 route-map RM-CC-CLOUD02
            network 10.47.20.0/25 route-map RM-CC-CLOUD02-A
            network 10.47.10.0/24 route-map RM-CC-CLOUD02-AGGREGATE

DAPnet Directly Accessible Private Network
##########################################
The driver supports tenant networks that are router internal (Neutron Router is the default gw) 
but exempt from NAT. Those networks are identified in Neutron by comparing the address-scope
of a routers internal and external network, if they match it is assumed that no NAT is required 
since the scope is the same. The driver needs to identify if there are tenant routers in a subnet 
and if those currently have DAPnets assigned to them. If this is the case the fabric as the upstream 
router must have routes set to those networks pointing to the respective tenant router.

Sample DAPnet Definition
------------------------
::

   ######### Example External Network
   {
     "id": "aeec9fd4-30f7-4398-8554-34acb36b7712",
     "ipv4_address_scope": "24908a2d-55e8-4c03-87a9-e1493cd0d995",
   }

   ####### Router Port which is next hop for DAPnet
   {
   "binding_vif_type": "asr1k",
   "device_owner": "network:router_gateway",
   "fixed_ips": [
     {
       "subnet_id": "bbe371ae-341b-4f86-931a-e9c808cb312e",
       "ip_address": "10.47.8.197"
     }
   ],
   }

   ######### Example DAPnet Network
   {
     "id": "8a307448-ef2a-4cae-9b2a-2edf0287e194",
     "ipv4_address_scope": "24908a2d-55e8-4c03-87a9-e1493cd0d995",
   }

   ######### Example DAPnet Subnet
   {
     "cidr": "10.47.100.0/24",
     "gateway_ip": "10.47.100.1",
     "host_routes": [],
     "id": "ab16807f-9c82-45e8-8e8d-da615eb8505a",
     "ip_version": 4,
     "name": "FloatDAPnet Sample 1",
     "network_id": "8a307448-ef2a-4cae-9b2a-2edf0287e194",
     "subnetpool_id": "e8556528-01e6-4ccd-9286-0145ac7a75f4",
   }

On Device configuration
-----------------------

**EOS**:
::

   ip route vrf CC-CLOUD02 10.47.100.0/24 10.47.8.197

   router bgp 65130.1103
      vrf CC-CLOUD02
         network 10.47.100.0/24 route-map RM-CC-CLOUD02-A

**NX-OS**:
::

   vrf context CC-CLOUD02
      ip route 10.47.100.0/24 10.47.8.197

   router bgp 65130.1103      
      vrf CC-CLOUD02
         address-family ipv4 unicast
            network 10.47.100.0/24 route-map RM-CC-CLOUD02-A

***********
Subnet Pool
***********

The external subnets which are fabric relevant are identified by being created from 
a subnet pool belonging to an address-scope which is listed in the driver configuration.
If a subnet is matching this criteria it is created as described in the subnet section.
In addition the driver will manage summarization of routes from and across subnet pools
within the same address-scope. The summary routes are maintained on the pod leafs the 
suppression of more specific prefixes towards core routing is done on the leaf
connecting to the upstream router, this is done by maintaining a prefix list filtering
out undesired prefixes. It is assumed this list will be used in BGP policy towards
core routers, policy and bgp configuration for those peerings are not in scope 
of the driver managed configuration. For each vrf the driver will do:

1. Collect all address-scopes belonging to the vrf
2. Continue processing individually for each AZ and Regional address-scopes
3. From the subnet pools collect all prefixes
4. Compress the list by merging all adjacent prefixes (supernetting)
5. Remove all list entries where there exists a subnet equal to the entry (summary would conflict subnet)
6. Add the appropriate RM-CC-CCLOUDXX-AGGREGATE route-map to local subnets that match a supernet
7. Add BGP aggregate-address entry for remainder of list with the appropriate RM-CC-CCLOUDXX-AGGREGATE route-map

.. figure:: figure/subnet_aggregation_flow.svg
    :width: 300px
    :align: center
    :figclass: align-center

Driver Configuration
####################

::

   [address-scope:hcp03-public]
   export_rt_suffix = 102
   import_rt_suffix = 102
   vrf = cc-cloud02

   [address-scope:bs-public]
   export_rt_suffix = 102
   import_rt_suffix = 102
   vrf = cc-cloud02

   [address-scope:bs-public-a]
   availability_zone = a
   export_rt_suffix = 1102
   import_rt_suffix = 1102
   vrf = cc-cloud02

   [address-scope:bs-public-b]
   availability_zone = b
   export_rt_suffix = 2102
   import_rt_suffix = 2102
   vrf = cc-cloud02

Sample Subnet Pool Definition
#############################

::

   {
     "id": "f2fd984c-45b1-4465-9f99-e72f86b896fa",
     "ip_version": 4,
     "name": "hcp03-public",
   }
   {
     "id": "10c48c80-b250-4452-a253-7f88b7a0deec",
     "ip_version": 4,
     "name": "bs-public",
   }
   {
     "id": "ff3452d0-c968-49c6-b1c7-152e5ffb11ae",
     "ip_version": 4,
     "name": "bs-public-a",
   }

   {
    "address_scope_id": "f2fd984c-45b1-4465-9f99-e72f86b896fa",
    "id": "e6df3de0-16dd-46e3-850f-5418fd6dd820",
    "ip_version": 4,
    "name": "sap-hcp03",
    "prefixes": [
      "130.214.202.0/25",
      "10.188.16.0/21",
      "10.236.100.0/22"
    ],
   }
   {
    "address_scope_id": "10c48c80-b250-4452-a253-7f88b7a0deec",
    "id": "438157b9-3ce3-4370-8bb5-59131ff105f9",
    "ip_version": 4,
    "name": "internet-bs",
    "prefixes": [
      "130.214.202.0/25",
      "130.214.215.0/26"
    ],
   }
   {
    "address_scope_id": "ff3452d0-c968-49c6-b1c7-152e5ffb11ae",
    "id": "438157b9-3ce3-4370-8bb5-59131ff105f9",
    "ip_version": 4,
    "name": "internet-bs",
    "prefixes": [
      "130.214.215.64/26"
    ],
   }

   {
     "cidr": "10.188.16.0/21",
     "id": "5051685d-37c5-4bab-98bf-8e797453ab03",
     "ip_version": 4,
     "name": "FloatingIP-sap-hcp03-03",
     "subnetpool_id": "e6df3de0-16dd-46e3-850f-5418fd6dd820",
   }

On Device Configuration
#######################

aPOD/vPOD/stPOD/netPOD/bPOD/Transit leafs
-----------------------------------------

**EOS**:
::

   router bgp 65130.1103
      vrf CC-CLOUD02
         aggregate-address 130.214.202.0/24 attribute-map RM-CC-CCLOUD02-AGGREGATE
         aggregate-address 130.214.215.0/26 attribute-map RM-CC-CCLOUD02-A-AGGREGATE
         aggregate-address 10.236.100.0/22 attribute-map RM-CC-CCLOUD02-AGGREGATE

**NX-OS**:
::

   router bgp 65130.1103
      vrf CC-CLOUD02
         address-family ipv4 unicast
            aggregate-address 130.214.202.0/24 attribute-map RM-CC-CCLOUD02-AGGREGATE
            aggregate-address 130.214.215.0/26 attribute-map RM-CC-CCLOUD02-A-AGGREGATE
            aggregate-address 10.236.100.0/22 attribute-map RM-CC-CCLOUD02-AGGREGATE

***********
Floating IP
***********

The high churn rate and mac-to-ip mobility cause significant ARP traffic in the fabric if 
not otherwise mitigated. To reduce the number of ARP packets required the driver will
in combination with the Neutron L3 driver create and maintain static arp entries to 
reduce the number of ARP packets significantly and allow for Floating Ip operations to 
be instantaneous. Static ARP entries will be defined on every leaf pair a certain 
FIP is expected to be at. If there are multiple leaf pairs where the IP could be located
it is expected that only the leaf pair also having the destination MAC in its local 
endpoint table generate a Type-2 MAC/IP route for the entry. Other leafs are not 
to generate Type-2 until such point as the destination MAC address becomes active 
at that leaf.

Sample Floating IP Definition
#############################
::

   # Neutron Router external Port connected to netPOD leaf serving the Floating IP
   {
     "binding_vif_type": "asr1k",
     "device_owner": "network:router_gateway",
     "mac_address": "fa:16:3e:6d:d3:33",
   }
   {
     "fixed_ip_address": "10.180.1.7",
     "floating_ip_address": "10.47.104.75",
     "floating_network_id": "aeec9fd4-30f7-4398-8554-34acb36b7712",
     "id": "fb8a5ddd-611b-415a-8bd7-64d3033ab840",
     "router_id": "260c2d26-2904-4073-8407-7f94ed1e88b8",
   }

On Device Configuration
#######################

netPOD leafs
-----------------------------------------

**EOS**:
::

   arp vrf CC-CLOUD02 10.47.104.75 fa16.3e6d.d333

**NX-OS**:
::

   interface vlan 3150
     vrf member CC-CLOUD02
     ip arp 10.47.104.75 fa16.3e6d.d333

***********
Port
***********
The driver handles multiple types of ports or port binding requests,
for all requests the driver manages the top level segment, segment creation for HPB
and configuring the relevant front ports for handing off networks 
to attached equipment which is configured by a ml2 driver further down the processing
chain and execute final port binding. For bare metal ports / servers directly
attached to the fabric the driver will do the final port binding as no 
other driver is subsequently called.

VLAN Handoff
############
This type of handoff is the most commonly used, the driver will allocate 
and configure a VNI to VLAN mapping (HPB segment) on all leaf switches relevant for the 
hostgroup in the port binding request as well as adding the vlan to all relevant ports on the switches.
The subsequent driver will pick up the partial binding and use the provided vlan information to configure
the attached device accordingly and finalize the port binding afterwards.

In addition to the Neutron networks in question the relevant infra networks defined in driver configuration
for the ports will be added.

Sample Driver Config
--------------------
::

  hostgroups:
     - binding_hosts:
       - node001-bb301
       members:
       - name: Ethernet1/1
         switch: qa-de-3-sw1103a-bb301
       - name: Ethernet1/1
         switch: qa-de-3-sw1103b-bb301
     - binding_hosts:
       - node002-bb301
       members:
       - name: Port-Channel 201
         switch: qa-de-3-sw1103a-bb301
         lacp: true
         members: [Ethernet3/1]
       - name: Port-Channel 201
         switch: qa-de-3-sw1103b-bb301
         lacp: true
         members: [Ethernet3/1]
     - binding_hosts:
       - nova-compute-bb301
       members:
       - node001-bb301
       - node002-bb301
       infra_networks:
       - vni: 10301100
         vlan: 100
         untagged: true
       - vni: 10301101
         vlan: 101
       metagroup: true

Sample Port Definition
----------------------
::

  # Network
  {
    "id": "aeec9fd4-30f7-4398-8554-34acb36b7712",
    "segments": [
      {
        "provider:network_type": "vlan",
        "provider:physical_network": "bb301",
        "provider:segmentation_id": 3150
      },
    ],
  }
  # Port
  {
  "admin_state_up": true,
  "binding_host_id": "nova-compute-bb301",
  "binding_profile": {},
  "binding_vif_details": {
    "segmentation_id": 3150
  },
  "device_owner": "compute:eu-de-1d",
  "id": "7574c44b-a3d7-471f-89e5-f3a450181f9a",
  "network_id": "aeec9fd4-30f7-4398-8554-34acb36b7712",
  }

VMware NSX-t, Neutron Network Agent, Octavia F5, Netapp, Ironic UCS, Neutron ASR ml2
------------------------------------------------------------------------------------
**EOS**:
::

  interface Ethernet1/1
     description "connect to node001-bb301"
     no shutdown
     switchport
     switchport mode trunk
     switchport trunk allowed 100,101,3150
     switchport trunk native vlan 100
     switchport trunk group $tenant-1 
     storm-control broadcast level 10
     spanning-tree portfast               
     errdisable recovery cause bpduguard    
     errdisable recovery interval 300        

  interface Ethernet3/1
     description "connect to node002-bb301"
     no shutdown
     channel-group 201 active

  interface Port-Channel201
     description "connect to node002-bb301"
     port-channel min-links 1
     no shutdown
     switchport
     switchport mode trunk
     switchport trunk allowed 100,101,3150
     switchport trunk native vlan 100
     storm-control broadcast level 10
     spanning-tree portfast               
     errdisable recovery cause bpduguard    
     errdisable recovery interval 300        
     port-channel lacp fallback static
     port-channel lacp fallback timeout 100

**NX-OS**:
::

  TBD

Ironic Bare Metal Ports
-----------------------

VXLAN EVPN Handoff
##################

VXLAN Flood and Learn Handoff
#############################

**************
Scaling Limits
**************

.. list-table:: Relevant Device Scaling Limits
   :widths: 33 33 33
   :header-rows: 1

   * - Resource
     - EOS
     - NX-OS
   * - VLANs
     - 1.800
     - 
   * - VRFs
     - 128
     -
   * - VLAN Translations (per Port)
     - n/a
     - 4.000 / 500 (FX3)
   * - VLAN Translations (per Switch)
     - 16.000
     - 24.000 / 6.000 (FX3)
   * - Static ARP entries
     -
     - 
   * - Static IPv4 Routes
     - 30.000
     - 
