Generator Input
~~~~~~~~~~~~~~~

The driver configuration is generated based on input from external tooling (Netbox) and the following conventions.

*********
Leaf Pair
*********

All EVPN fabric members will be of the following Netbox roles:

* **EVPN Spine**: Used for all spine switches, not configured by driver
* **EVPN Leaf**: Used for all leaf switches in the EVPN fabric
 
Hostname Convention
#########################

Leaf pair hostnames must be compliant with the following regex::

    ^(?P<region>\w{2}-\w{2}-\d)-sw(?P<az>\d)(?P<pod>\d)(?P<switchgroup>\d{2})(?P<leaf>[ab])(?:-(?P<role>[a-z0-9-]+))$

Or in a more readable way::
    
    [region]-sw[az][pod][switchgroup][leaf][role]
    i.e.: eu-de-1-sw4223a-bb147


Where the following conditions apply to the variables:

region:
    in the fashion like 'eu-de-1',

Each leaf pair (MLAG/VPC) requires a fabric unique 4 digit ID ([az][pod][switchgroup]) with an a/b identifier for leaf in group per leaf pair used to generate device specific configuration settings (ASN etc.)

az:
    single digit indicating the AZ, 1: AZ a, 2: AZ b, ...
pod:
    single non zero digit indicating the pod
switchgroup:
    a 2 digit number uniquely identifying the leaf pair in a region
leaf:
    a=fist leaf in pair, b=second leaf in pair
role: 
    optional, any sequence of numbers and lower case digits, such as bb147

Netbox Query::

    Role: EVPN Leaf
    Name: .*(\d\d\d\d)([a-b]).* #\1=leaf_id \2=leaf_a_b


Leaf Types
################
All fabric leaf switches must be tagged with exactly one of below subrole identifiers.

CCloud Pod Leaves
--------------------
Any leaf connecting any CC platform equipment must be tagged with the applicable tag of the following::

    CC-APOD|CC-BPOD|CC-NETPOD|CC-STPOD|CC-VPOD

Netbox Query::

    Role: EVPN Leaf
    Name: .*(\d\d\d\d)([a-b]).* #\1=leaf_id \2=leaf_a_b
    Tag: CC-APOD|CC-BPOD|CC-NETPOD|CC-STPOD|CC-VPOD

CND EVPN Leaf Types:
----------------------
The driver needs to identify certain non-pod leaf pairs to 
push tenant configuration:

* **CND-NET-EVPN-BL**: Border leaf connecting to core routing, required for subnet pool summarization
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

If for a device a different (or reduced) range is in effect it must be expressed in the Netbox device config context as a list of single values or ranges for that device, ranges are including first and last value

::

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


Infrastructure Networks
########################

Infrastructure networks (infra networks) are required to deliver the platform's control plane communication.
These can be used for hypervisor specific purposes, management access or provisioning.

Infra networks can be pure layer 2 networks or routed layer 3 networks with an anycast gateway bound on the leaf switch.
Pure layer 2 infra networks will be modelled using Netbox *VLAN groups* and *VLANs*. If a infra network is layer 3 enabled,
we use Netbox *prefixes* and *IP address* objects to associate the layer 3 portion.

Each pod must have its infra *VLAN* created in a *VLAN group*. *VLAN groups* must have the *site* of the pod assigned.
The group must be named in accordance with the pod type. Find the following exemplary python code for illustration:

::

    import pynetbox
    nb = pynetbox.api(...)
    site = nb.dcim.sites.get(slug='qa-de-1d')
    bb = 271
    pod_type = 'CC-vPOD'
    vgroup = nb.ipam.vlan_groups.create({'name': f'{pod_type}{bb:03d}', 'slug': f'{pod_type.lower()}{bb:03d}', site=site.id})


::

    pod_type: aPOD|CC-bPOD|CC-netPOD|CC-stPOD|CC-vPOD
    pod_number: a 3 digit zero-padded number indicating the pod

Each infra network must be present in Netbox as a *VLAN* object in the corresponding *VLAN group*, with correct *site* and *role* assignments.
::

    mgmt_role = nb.ipam.roles.get(slug='cc-management')
    cc_tenant = nb.tenancy.tenants.get(slug='converged-cloud')
    mgmt_vlan = nb.ipam.vlans.create({'name': 'BB Mgmt','role': mgmt_role.id, 'site': site.id,
                          'tenant': cc_tenant.id, 'group':vgroup.id, 'vid': 101, 'status': 'active'})

Any layer 3 infra network local to that building-block must subnetted from a precreated building-block specific supernet.
We retreive the precreated network assignments follows:
::

    cc_mgmt_vrf = nb.ipam.vrfs.get(name='CC-MGMT')
    candidate_nets = [x for x in nb.ipam.prefixes.filter(role='cc-building-block', site_id=site.id, vrf_id=cc_mgmt_vrf.id) 
                      if x.description.startswith(f'BB{bb:03d}')]
    if len(candidate_nets) != 1:
        raise ValueError(f'Could not find a mgmt supernet for BB{bb:03d} or found more than 1')
    bb_net = candidate_nets[0]

Any layer 3 infra network must be created as a prefix object in Netbox. The prefix object must carry the correct *VRF* assignment, 
*tenant*, *VLAN* association, *role* assignment. It must be set to active and may not be a pool.
::
    
    from ip_address import ip_network

    prefixes_26 = list(ip_network(mgmt_net.prefix).subnets(new_prefix=26))
    prefixes_27 = list(ip_network(mgmt_net.prefix).subnets(new_prefix=27))

    mgmt_prefix = nb.ipam.prefixes.create({ 'family': 4, 'vrf': cc_mgmt_vrf.id, 'tenant': cc_tenant.id,
                                            'prefix': str(prefixes_26[1]), 'site': site.id, 'vlan': mgmt_vlan.id,
                                            'role': mgmt_vlan.role.id, 'status': 'active', 'is_pool': False})

Anycast Gateway
------------------
If a local anycast gateway for an layer 3 infra network shall be configured, a corresponding  SVI interface must be created in Netbox in order to reflect the anycast gateway.
The SVI interface must be created on both leaf switches of a pod and must be exactly named as SVI interfaces are named
in the device specific configuration. Each SVI interface must have an *IP Address* object linked that associates to
the *VRF* it routes and must be of type *anycast*.
An SVI interface must also have the VLAN it corresponds to set as *unatagged_vlan*. Find the details in below code snippet:
::

    prefix = ip_network(mgmt_prefix.prefix)
    gateway = f'{next(prefix.hosts())}/{prefix.prefixlen}' # always first address of network
    for leaf in leaves:
        # f'Vlan{id}' is naming compliant to Arista EOS
        svi = nb.dcim.interfaces.create(
            {'name': f'Vlan{mgmt_vlan.vid}', 'device': leaf.id, 'type': 'virtual', 'unatagged_vlan': mgmt_vlan.id, 'mode': 'access' })
        nb.ipam.ip_addresses.create({
            'address': gateway, 'family': 4, 'vrf': cc_mgmt_vrf.id,
            'tenant': cc_tenant.id, 'status': 'active', 'role': 'anycast',
            'assigned_object_type': 'dcim.interface', 'assigned_object_id': svi.id})


DHCP Relay
-------------------

For infra networks requiring a DHCP relay one or more Netbox *Tags* 
must be added to the *VLAN* object, one for each DHCP relay server
in the form::

    CC-NET-EVPN-DHCP-RELAY:10.10.10.10
    CC-NET-EVPN-DHCP-RELAY:10.11.11.11

L2 Networks VLAN to VNI mapping
##################################
Netbox does not yet support a model for overlay network VNIs, the following conventions are used:

+---------------------+-----------------------------------------------------------+
| Network Type        | VNI Allocation                                            |
+=====================+===========================================================+
| Infra Regional      | VLAN X uses VNI X (VLAN 100 -> VNI 100)                   |
+---------------------+-----------------------------------------------------------+
|| Infra AZ-wide      || VLAN X uses VNI [AZ-Prefix]X                             |
||                    || i.e VLAN 800, AZ=a -> 100800, VLAN = 800, AZ=b -> 200800 |
+---------------------+-----------------------------------------------------------+
|| Infra Pod-specific || VLAN X re-used in many pods as local vlan,               |
||                    || 1PPPPVVV with P=Pod ID 4-Digit with leading zeros,       |
||                    || V=Local VLAN id 3-Digit with leading zeros.              |
||                    || i.e Vlan 100 in vPOD 371 -> VNI=10371100                 |
+---------------------+-----------------------------------------------------------+
| Tenant              | CCloud platform driver should use range 10000 - 99999     |
+---------------------+-----------------------------------------------------------+



**************************
Ports and Interfaces
**************************
The driver is responsible for front ports on pod equipment, configures certain infra networks on such ports or
bundles ports in LAG and MLAG logical interfaces. This section describes Netbox modelling requirements for the driver's input.

Cables
############
All cables must be modelled according to physical connections. Cables must be marked as `installed` when installed.
This does also include Leaf to Spine links, which are necessary for diagnostic tooling.



Link Aggregation Groups
########################
There are two types Link Aggregation Groups (LAGs)), static which are defined in Netbox as LAG
with member interfaces and dynamic which are defined via CCloud port groups self service.

To ensure LAG definitions do not conflict, the id range is distinct for 
both use cases as follows.

.. list-table:: LAG Ranges
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

Static LAGs must be defined in Netbox by creating a new interface of type *LAG*, the interface must be *enabled*. A LAG interface's
name must exact-match the full name in the vendor specific configuration, i.e *Port-Channel* for Arista EOS, *Port-channel* for Cisco NXOS.
All member interfaces must be made a member of the LAG interface in Netbox.

LAGs can either have ports only on one leaf or be spanned across two leaves (MLAG/vPC).
The following convention will be used to distinguish the two 
variants::

    port-channel100 defined on device 1110a only: a regular port-channel will be configured
    port-channel100 defined on device 1110a AND 1110b: a MLAG/vPC will be configured


Infrastructure Network Assignment
###################################

In order to bind infra networks to interfaces, the *VLAN* must be bound to the *interface* object in Netbox.
*VLANs* must only be bound to the logical interface, so if an interface is a LAG member, the VLAN object must be bound on the LAG.

*VLANs* can either be bound as *tagged_vlans* or one VLAN may be bound as *untagged_vlan* on the interface.
The interface mode must be set to 'tagged' in order to server the 'tagged_vlans'.

Our current use case only includes tagged infra networks, which derives to the following snippet::
    
    # server_interfaces: all interfaces on both leaf switches on a building block that are connecting a server
    infra_vlans = [vlan_console, vlan_mgmt, vlan_vmotion, vlan_backdoor]
    for i in server_interfaces:
        i.mode = 'tagged'
        i.tagged_vlans = infra_vlans
        i.save()
