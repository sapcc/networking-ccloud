Driver Configuration
~~~~~~~~~~~~~~~~~~~~

Example Configuration
#######################

The top level configuration looks as follows:
::

    global_config: *global-config
    hostgroups: *hostgroups
    switchgroups: *switchgroups

:code:`global_config`
######################

::

    global_config: &global-config
      asn_region: '65130'
      availability_zones:
      - name: qa-de-1d
        number: 4
        suffix: d
      vrfs:
      - name: CC-CLOUD02
        number: 102

:code:`hostgroups`
######################

Hostgroups map multiple OpenStack binding hosts to a set of switch ports. A hostgroup may be a metagroup in which case its members are hostgroups again. This can be used to aggregate hosts to a group.
A hostgroup may have the `direct_binding: true` property in which case no further driver will be called to bind the host.
Members of a hostgroup that is not a metagroups must be references to a switchport.
A hostgroup's default physical network is the physical network of the switchgroup that is associated by its members.

::

    hostgroups: &hostgroups
    - binding_hosts:
      - node001-bb271
      direct_binding: true
      members:
      - lacp: true
        members:
        - Ethernet1/1
        name: Port-Channel101
        switch: qa-de-1-sw4113a-bb271
      - lacp: true
        members:
        - Ethernet1/1
        name: Port-Channel101
        switch: qa-de-1-sw4113b-bb271
    - binding_hosts:
      - node002-bb271
      direct_binding: true
      members:
      - lacp: true
        members:
        - Ethernet2/1
        name: Port-Channel102
        switch: qa-de-1-sw4113a-bb271
      - lacp: true
        members:
        - Ethernet2/1
        name: Port-Channel102
        switch: qa-de-1-sw4113b-bb271
    - binding_hosts:
      - nova-compute-bb271
      direct_binding: false
      infra_networks: *infra_networks
      extra_vlans: *extra_vlans
      members:
      - node001-bb271
      - node002-bb271
      metagroup: true

.. _Infrastructure Network Config:

:code:`infra_networks`
######################

Infrastructure networks (:code:`infra_networks`) are required to deliver the platform's control plane communication.
They can be used for hypervisor specific purposes, management access or provisioning and can be pure layer 2 networks or routed layer 3 networks with an anycast gateway bound on the leaf switch.
If the network is supposed to be layer 3, a network and VRF must be provided. BGP aggregates may also be provided and will additionally be sourced from all switches the hostgroup is a member of.
Infrastructure Networks will be preconfigured by the driver without the presence of any OpenStack object.
If an Infrastructure Network is defined on a metagroup, it will be configured on all members of that metagroups.

::

      infra_networks: &infra_networks
      - name: bb271-bb-console
        vlan: 100
        vni: 10271100
      - aggregates:
        - 10.11.12.0/24
        name: bb271-bb-mgmt
        networks:
        - 10.11.12.65/26
        vlan: 101
        vni: 10271101
        vrf: MGMT
      - aggregates:
        - 10.11.12.0/24
        name: bb271-bb-vmotion
        networks:
        - 10.11.12.193/27
        vlan: 104
        vni: 10271104
        vrf: MGMT
      - aggregates:
        - 10.11.12.0/24
        name: bb271-bb-backdoor-management
        networks:
        - 10.11.12.225/27
        vlan: 106
        vni: 10271106
        vrf: MGMT

.. _extra VLAN Config:

:code:`extra_vlans`
####################

The driver assumes full control over a managed interface's allowed VLAN list. Hence any VLAN not known by the driver would be removed from the allowed VLAN list causing unwanted side effects. In the unfortunate case of VLANs that are not driver provisioned but still need to be on a driver managed port, the extra_vlans list comes into play. Extra VLANs on a metagroup will be programmed on all ports of metagroup memebers.

::

  extra_vlans: &extra_vlans
  - 101
  - 202
  - 406

:code:`switchgroups`
######################

::

    switchgroups: &switchgroups
    - asn: '65130.4113'
      availability_zone: qa-de-1d
      group_id: 4113
      members:
      - bgp_source_ip: 4.1.13.1
        host: 192.168.1.146
        name: qa-de-1-sw4113a-bb271
        password: ive-been-looking-for-vlans
        platform: arista-eos
        user: the_hoff
      - bgp_source_ip: 4.1.13.2
        host: 192.168.1.147
        name: qa-de-1-sw4113b-bb271
        password: ive-been-looking-for-vlans
        platform: arista-eos
        user: the_hoff
      name: bb271
      vtep_ip: 4.1.13.0
