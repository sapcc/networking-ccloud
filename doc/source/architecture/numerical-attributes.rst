Numerical Attributes
--------------------------

There a a variety of data plane and control plane protocol resources that need to be shared between the driver and any entity that configures backbone protocols. This pages gathers driver responsible resources and explains there generations.

Driver Responsible Ranges
=========================

.. list-table:: Ranges
   :header-rows: 1
   :widths: 10, 10, 10, 70

   * - Config Object
     - Significance
     - Correpsonding OpenStack Resource
     - Managed Ranges
   
   * - interface, eg. `Ethernet1`
     - switch
     - `binding_host` or `metagroup`
     - all interfaces appearing in the driver config

   * - LAG, eg. `Port-Channel101`
     - switch
     - lag assignment in driver config
     - | all interfaces appearing in the driver config,
       | numbers will not be allocated by driver but by netbox/netbox-modeller,
       | see :ref:`LAG Ranges`

   * - VLAN id
     - switchgroup
     - segment or `infra_network` in driver config
     - | driver allocates VLANs in the range of 2000-3750,
       | a VLAN assigned to an  `infra_network` in the driver config bound to a `switchgroup` [1]_ will be controlled on that switchgroup.

   * - VXLAN VNI
     - region
     - network
     - | driver allocates VNIs in the 10000 - 65535
       |
       | a VNI assigned to an  `infra_network` in the driver config bound to a `switchgroup` [1]_  will be controlled on that switchgroup,
       | VNIs assigned through driver config must follow the :ref:`vlan-to-vni`.

   * - L2 EVPN RD
     - region
     - network
     - | dependent on VNI allocation, using type 0 formatting:
       |
       | `administrative subfield`: :code:`f{switchgroup_id}`
       | `assigned number subfield`: :code:`f{vni_id}`
       | resulting in RD for VNI 12666 on switchgroup 1112 in AZ D: :code:`1112:12666`

   * - L2 EVPN RT
     - region
     - network
     - | dependent on VNI allocation, using type 0 formatting:
       |
       | `administrative subfield`: :code:`f{az_number}`
       | `assigned number subfield`: :code:`f{vni_id}`
       | resulting in RT for VNI 12666 in AZ D: :code:`4:12666`

   * - L3 EVPN RD and RT
     - region
     - external network with subnet
     - | not maintained by the driver, but preconfigured,
       | dependent on VRF affinity, using type 2 formatting:
       |
       | `administrative subfield`: :code:`f'{switch_asn}'`
       |
       | if the external network has an `az_hint`:
       | `assigned number subfield`: :code:`f'{az_number}1{vrf_id:02d}'`
       | resulting in RD and RT an external az-hinted network in AZ D in VRF 76: :code:`65130.4122:4176`
       |
       | else:
       | `assigned number subfield`: :code:`f'1{vrf_id:02d}'`
       | resulting in RD and RT an external az-hinted network in AZ D in VRF 23: :code:`65130.4122:176`


.. [1] Attributes of an `infra_network` are transitively assigned to the switchgroup by the hostgroups reference to a switchgroup


Driver Managed Networks
========================
There are 2 ways in which the driver manages Networks, either wholistically or just in the allowed VLAN list. Please see :ref:`Infrastructure Network Config` and :ref:`extra VLAN Config` for details.

The following list will provide an overview for driver managed Infrastructure Networks or extra VLANs in our Infrastructure. It does not aim to be complete or up-to-date. Authoritative data is found in the driver config or in Netbox. See :ref:`Infrastructure Networks from Netbox` and :ref:`extra VLANs from Netbox` for details

.. list-table:: Driver Managed Networks
   :header-rows: 1
   :widths: 35, 35, 15, 15

   * - Name
     - Identified by
     - Pod Roles
     - Type of Management
   
   * - vPOD Infra Networks
     - VID 101-107 in every vPOD
     - vPOD
     - Infrastructure Network

   * - SWIFT Node MTU Replication Network
     - VID 101 in `f'{region}-regional` VLAN group
     - stPOD
     - extra VLAN

   * - SWIFT Node Infra Networks
     - VID 754-756 in `f'{region}-cp` VLAN group
     - stPOD
     - extra VLAN

   * - SWIFT Node K8S Peering Network
     - VID 901 in `f'{region}-cp` VLAN group
     - stPOD
     - extra VLAN

   * - Manila Replication Network
     - global VID 981
     - stPOD
     - extra VLAN
