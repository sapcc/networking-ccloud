Generator Input
~~~~~~~~~~~~~~~

The driver configuration is generated based on input from external toooling (Netbox) and the following conventions.

*********
Leaf Pair
*********

All EVPN fabric members will be of the following Netbox roles:

* **EVPN Spine**: Used for all spine switches, not configured by driver
* **EVPN Leaf**: Used for all leaf switches in the EVPN fabric
 
Uniq Pair ID
############
Each leaf pair (MLAG/VPC) requires a fabric uniq 4 digit ID (XYZZn) with an a/b identifier for leaf in group per leaf pair used to generate device specifig configuration settings (ASN etc.)

* X: CCloud AZ a=1, b=2, etc.
* Y: EVPN Spine POD in AZ 1,2,3... etc.
* ZZ: Two digit uniq leaf pair identifier 01-99
* n: a=fist leaf in pair, b=second leaf in pair

Netbox Query::

    Role: EVPN Leaf
    Name: .*(\d\d\d\d)([a-b]).* #\1=leaf_id \2=leaf_a_b

CCloud Pod leafs
################
All CCloud pod types will be tagged to the leaf to identify sub-role:

Netbox Query::

    Role: EVPN Leaf
    Name: .*(\d\d\d\d)([a-b]).* #\1=leaf_id \2=leaf_a_b
    Tag: CC-APOD|CC-BPOD|CC-NETPOD|CC-STPOD|CC-VPOD

CND EVPN leaf types:
####################
The driver needs to identify certain non-pod leaf pairs to 
push tenant configuration:

* **CND-NET-EVPN-BL**: Border leaf connectng to core routing, required for subnet pool summarization
* **CND-NET-EVPN-TL**: Transit leaf connecting to a legacy fabric for migration purposes
* **CND-NET-EVPN-BG**: Used for all gateways interconnecting CC AZ's in a multi AZ fabric
 
Netbox Query::

    Role: EVPN Leaf
    Name: .*(\d\d\d\d)([a-b]).* #\1=leaf_id \2=leaf_a_b
    Tag: CND-NET-EVPN-TL

    Role: EVPN Leaf
    Name: .*(\d\d\d\d)([a-b]).* #\1=leaf_id \2=leaf_a_b
    Tag: CND-NET-EVPN-BG

    Role: EVPN Leaf
    Name: .*(\d\d\d\d)([a-b]).* #\1=leaf_id \2=leaf_a_b
    Tag: CND-NET-EVPN-BL

**************
L2/L3 Networks
**************

Tenant Network VLAN range
#########################
The VLAN range segments should be allocated from is per convention defined as::

    2000-3750

If for a device a different (or reduced) range is in effect it must be expressed in the Netbox device config context as a list of single values or ranges for that device, ranges are including first and last value::

    {
    "cc": {
        "net": {
            "evpn": {
                "tenant-vlan-range": [
                    "2000",
                    "2100-3000"
                ],
            }
        }
    }

Infra Network DHCP Relay
########################
For infra networks requiring a DHCP relay one or more Netbox Tags 
must be added to the vlan object, one for each dhcp relay server
in the form::

    CC-NET-EVPN-DHCP-RELAY:10.10.10.10
    CC-NET-EVPN-DHCP-RELAY:10.11.11.11

L2 Networks VLAN to VNI mapping
###############################
Netbox does not yet support a model for overlay network VNIs, the following conventions are used

* **Infra Regional**: VLAN X uses VNI X (VLAN 100 -> VNI 100)
* **Infra AZ-wide**: VLAN X uses VNI [AZ-Prefix]X (VLAN 800, AZ=a -> 100800, VLAN 800, AZ=b -> 200800)
* **Infra Pod-specific**: VLAN X re-used in many pods as local vlan, 1PPPPVVV with P=Pod ID 4-Digit with leading zeros, V=Local VLAN id 3-Digit with leading zeros. Vlan 100 in vPOD 371 -> VNI=10371100
* **Tenant**: CCloud platform driver should use range 10000 - 99999


*****
Ports 
*****
the driver is responsible for front ports on pod equipment, some port types require 
certain infra VLANs to be provisioned as well as ports being assembled into port-channels
based on current port function

Port infra VLANs
################
Infra VLAN's required on ports are recorded on the Netbox port they are reuqired on,
for port-channels the required vlans do only need to be provided on the LAG interface,
VLAN's defined on member interfaces will be ignored for port-channel members:

Netbox config::

    "802.1Q Mode" = Tagged|Untagged
    "Untagged VLAN" = Single VLAN reference
    "Tagged VLAN's" = List of VLAN references

Port Channels
#############
There are two types port-channels, static which are defined in Netbox as LAG
with member interfaces and dynamic which are defined via CCloud port groups
self service.
To ensure port-channel definitions do not conflict the id range is distinct for 
both use cases as follows.

.. list-table:: Port-Channel Ranges
   :widths: 25 25 50
   :header-rows: 1

   * - Port-Channel ID
     - Type
     - Usage
   * - 1
     - Static
     - MLAG or vPC peer link
   * - 2-3
     - Static
     - reserved for admin switch connectivity
   * - 4-9
     - Static
     - reserved for future use
   * - 10-99
     - Static
     - reserved for non-driver controlled Port-channels
   * - 100-999
     - Dynamic
     - reserved for driver controlled Port-channels

Port-channels can either have ports only on one device or be spanned across two
devices (MLAG/vPC) the following convention will be used to distinguish the two 
variants::

    port-channel100 defined on device 1110a only: a regular port-channel will be configured
    port-channel100 defined on device 1110a AND 1110b: a MLAG/vPC will be configured

