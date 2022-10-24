Netbox Config Generator
~~~~~~~~~~~~~~~~~~~~~~~~
.. _`netbox_model.py`: https://github.com/sapcc/networking-ccloud/blob/HEAD/networking_ccloud/tools/netbox_modelr.py


Netbox Config Generator will fetch all devices that belong to below Netbox roles. It will then fetch all interfaces and create hostgroups from clusters that are connected to the interfaces.
The driver configuration is generated based on input from external tooling (Netbox). 

A reference how the Config Generator expects Netbox objects can be found in `netbox_model.py`_

Run
#####

The config generator is available under :code:`networking_ccloud/tools/netbox_config_gen.py` using the entrypoint :code:`cc-netbox-config-gen`.

It does support nesting the configuration under certain YAML keys if the config need to be picked up by helm. Use the :code:`--wrap-in` parameter for that.

Vault references can also be injected instead of plain-text passwords using the :code:`--vault-ref` parameter.

Example
--------

::

   cc-netbox-config-gen -r $OS_REGION_NAME -u MYAPIUSER -V $OS_REGION_NAME/my/vault/path -w cc_fabric/driver_config -o $PATH_TO_HELM_VALUES/$OS_REGION_NAME/values/neutron-cc-fabric.yaml



Managed Devices
#################

All fabric members must be of the following Netbox roles:

* **EVPN Spine**: Used for all spine switches, not configured by driver
* **EVPN Leaf**: Used for all leaf switches in the EVPN fabric

Devices can be explicitly ignored if they are tagged using the :code:`cc-net-driver-ignore` tag. Devices will be picked up when they are in state *staged* or *active*.

Hostnames
---------

Leaf pair hostnames must be compliant with the following regex::

    ^(?P<region>\w{2}-\w{2}-\d)-sw(?P<az>\d)(?P<pod>\d)(?P<switchgroup>\d{2})(?P<leaf>[ab])(?:-(?P<role>[a-z]+(?P<bb_no>[0-9]+)?))$

Or in a more readable way::
    
    [region]-sw[az][pod][switchgroup][leaf][role]
    i.e.: eu-de-1-sw4223a-bb147

Where the following conditions apply to the variables:

Each leaf pair (MLAG/VPC) requires a fabric unique 4 digit ID ([az][pod][switchgroup]) with an a/b identifier for leaf in group per leaf pair used to generate device specific configuration settings (ASN etc.)

.. list-table::

  * - region
    - in the fashion like 'eu-de-1',
  * - az
    - single digit indicating the AZ, 1: AZ a, 2: AZ b, ...
  * - pod
    - single non zero digit indicating the pod
  * - switchgroup
    - a 2 digit number uniquely identifying the leaf pair in a region
  * - leaf
    - a=fist leaf in pair, b=second leaf in pair
  * - role 
    - any sequence of lower case characters followed by digits as a pod identifier, such as bb147. The pod identifier is optional.

Each leaf pair (MLAG/VPC) requires a fabric unique 4 digit ID :code:`(f{az}{pod}{switchgroup})` with an a/b identifier for leaf in group per leaf pair used to generate device specific configuration settings (ASN etc.)

Leaf Types
-----------
All fabric leaf switches must be tagged with exactly one of below subrole identifiers.

CCloud Pod Leaves
..................
Any leaf connecting any CC platform equipment must be tagged with the applicable tag of the following:

* CC-APOD
* CC-BPOD
* CC-NETPOD
* CC-STPOD
* CC-VPOD


CND EVPN Leaf Types:
.....................
The driver needs to identify certain non-pod leaf pairs to 
push tenant configuration:

* **CND-NET-EVPN-BL**: Border leaf connecting to core routing, required for subnet pool summarization
* **CND-NET-EVPN-TL**: Transit leaf connecting to a legacy fabric for migration purposes
* **CND-NET-EVPN-BG**: Used for all gateways interconnecting CC AZ's in a multi AZ fabric

L2/L3 Networks
#################

Tenant Network VLAN range
---------------------------

The default VLAN range for any physnet will be assumed to be in the range from **2000-3750**.

If for a device a different (or reduced) range is in effect it must be expressed in the Netbox device config context as a list of single values or ranges for that device, ranges are including first and last value. This must look like the following:

::

    {
    "cc": {
        "net": {
            "evpn": {
                "tenant-vlan-range": [
                    "2000",
                    "2100:3000"
                ],
            }
        }
    }


.. _Infrastructure Networks from Netbox:

Infrastructure Networks
-------------------------
.. _`netbox_config_gen.py`: https://github.com/sapcc/networking-ccloud/blob/HEAD/networking_ccloud/tools/netbox_config_gen.py

also see :ref:`Infrastructure Network Config`.

Infrastructure Networks can be pure layer 2 or layer 3. These must be modelled in Netbox as follows in order to be picked up.

Layer 2 Infrastructure Networks need to have:

* A *VLAN* object with a corresponding *VLAN group*,
* *VLANs* must only be bound to the logical interface, so if an interface is a LAG member, the VLAN object must be bound on the LAG,
* a *VLAN group* with a naming scheme for which a VNI allocation logic is defined (currently only for cc-vpod *VLAN groups*, see :code:`derive_vlan_vni` in `netbox_config_gen.py`_  and vlan-to-vni_ for reference).

If an Infrastructure Network shall be layer 3 enabled, the following conditions need to be met additionally (see :code:`get_infra_network_l3_data` in `netbox_config_gen.py`_ for reference):

* The *VLAN* object must have a prefix associated,
* the prefix must have the correct VRF assigned,
* the prefix should be subnetted from the pod-specific management supernet if applicable,
* the prefix must have a parent prefix associated which will be added as an BGP aggregate to the config. 

In addition, we expect all layer 3 Infrastructure Networks to be anycast-gateway routed. As these anycast gateways live on the TOR leaf, those must be moddeled as follows:

* The SVI interface must be created on both leaf switches of a pod,
* the SVI interface must be exactly named as SVI interfaces are named in the device specific configuration,
* each SVI interface must have an *IP Address* object linked that associates to the *VRF* it routes and must be of type *anycast*,
* the SVI interface must also have the VLAN it corresponds to set as *unatagged_vlan*.

DHCP Relay (not implemented so far)
....................................
For infra networks requiring a DHCP relay one or more Netbox *Tags* 
must be added to the *VLAN* object, one for each DHCP relay server
in the form::

    CC-NET-EVPN-DHCP-RELAY:10.10.10.10
    CC-NET-EVPN-DHCP-RELAY:10.11.11.11


.. _extra VLANs from Netbox:

Extra VLANs
-------------------------
also see :ref:`extra VLAN Config`.

Whenever an extra VLAN is required, it needs to be modelled in Netbox in order to be picked up:

* There must be a *VLAN* object existing,
* the *VLAN* must be assigned to the logical port in *tagged* mode,
* the *VLAN* or its associated VLAN group must have the :code:`cc-net-driver-extra-vlan`.
  
As our Netbox version currently does not yet support tags on VLAN groups, we additionally consider the following VLANs as extra VLANs as long as Netbox is not upgraded:

* *VLAN group* name starts with region and ends with :code:`cp`
* *VLAN group* name is :code:`f'{region}-regional`
* *VLAN group* name is :code:`global-cc-core-transit`

.. _vlan-to-vni:

L2 Networks VLAN to VNI mapping
--------------------------------
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
| Tenant              | CCloud platform driver should use range 10000 - 65535     |
+---------------------+-----------------------------------------------------------+



Ports and Interfaces
#####################
The driver is responsible for front ports on pod equipment, configures certain infra networks on such ports or
bundles ports in LAG and MLAG logical interfaces. This section describes Netbox modelling requirements for the driver's input.

Cables
-------
All cables must be modelled according to physical connections. Cables must be marked as `installed` when installed.
This does also include Leaf to Spine links, which are necessary for diagnostic tooling.

Rules for Driver Managed Interfaces
----------------------------------------

All interfaces that have a connected endpooint which satisfies the following conditions will be picked up:

* *connected device* -> *device role* is one of *server*, *neutron-router*, *loadbalancer*, and
* the tenant is *Converged Cloud*, and
* the interface must be a member of a LAG in the driver managed LAG range, and
* there must not be a :code:`cc-net-driver-ignore` tag on the interface,

or

* *connected device* -> *device role* is *filer*, and
* the *connected device* has a *parent device* (a chassis it resides in), and
* the interface must be a member of a LAG in the driver managed LAG range, and
* the *parent device* is tagged with :code:`manila`.

If the one of the following conditions is met, the devices will also be gathered in a metagroup:

* the *connected device*'s cluster type is one of the following *cc-vsphere-prod*, *neutron-router-pair*, *cc-k8s-controlplane*, *cc-f5-vcmp*, or
* the *connected device*'s parent device is tagged with :code:`manila`.

Link Aggregation Groups
-----------------------

LAGs must be defined in Netbox by creating a new interface of type *LAG*, the interface must be *enabled*. A LAG interface's
name must exact-match the full name in the vendor specific configuration, i.e *Port-Channel* for Arista EOS, *Port-channel* for Cisco NXOS.
All member interfaces must be made a member of the LAG interface in Netbox.

The driver will assemble all lags that are known to it in its config. Within CCloud we must follow this convention
which is not policy enforced at the moment. However the netbox modeller will generate LAG-ids based on this.

LAGs can either have ports only on one leaf or be spanned across two leaves (MLAG/vPC).
The following convention will be used to distinguish the two 
variants::

    port-channel100 defined on device 1110a only: a regular port-channel will be configured
    port-channel100 defined on device 1110a AND 1110b: a MLAG/vPC will be configured

.. _LAG Ranges:
.. list-table:: LAG Ranges
   :widths: 25 50
   :header-rows: 1

   * - Port-Channel ID
     - Usage
   * - 1
     - MLAG or vPC peer link
   * - 2-3
     - reserved for admin switch connectivity
   * - 4-9
     - reserved for future use
   * - 10-99
     - reserved for non-driver controlled Port-channels
   * - 100-999
     - reserved for driver controlled Port-channels

Netbox Modeller LAG ID Generation
----------------------------------------
Driver controlled and hence netbox modeller generated LAGs have the ID space from 100-999.
We will generate the id based on the `interface index` and the `slot number`. `slot number` refers to either the
number of the linecard or the number of the interface that is broken out (if breakout cables are used). Interface index
refers to interface number within that linecard or breakout group. We will never form LAGs over multiple breakouts
or linecards. If multiple interfaces are used, the lowest `interface index` will be used.
The LAG ID will then be calculated using `slot_number * 100 + interface_index`.
