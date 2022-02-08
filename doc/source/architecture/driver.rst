CC-Fabric ML2 Driver Internals
------------------------------
NOTE: these are currently drafts and thoughts that have been recorded over the course of the project.
Some have been written before implementation, some while implementation was being done. Therefore they
might not be 100% accurate or need a review.

Structural Overview
~~~~~~~~~~~~~~~~~~~

DB, API and Config Objects & How They Match Together
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The following API objects are relevant for a network configuration:
 * ``network``
    * ``id`` - used as name / reference for this network
    * ``availability_zone_hints`` - used to decide if a port can be bound in this network
    * ``admin_state_up`` - **FIXME** should we respect this flag?
    * ``router:external`` - external or internal network
 * ``subnet`` - belongs to a single network, only relevant for external networks
    * ``gateway_ip``
 * ``port``
    * ``binding_host`` - host, which will be mapped to a hostgroup by the driver
    * ``binding_profile`` - alternative source for binding host (used by baremetal)
    * ``admin_state_up`` - **FIXME** should we respect this flag?

The following DB tables are relevant:
 * ``networksegments``
    * ``network_type`` - vxlan or vlan; the driver will only manage vlan segments (vxlan segments are managed by neutron, not us)
    * ``network_id`` - network_id this segment is relevant for
    * ``physical_network`` - name of the physnet (as defined by hostgroup in driver config)
    * ``segmentation_id`` - vni or vlan id
    * ``segment_index`` - level of segment, 0 is the top level vxlan segment, 1+ driver managed
 * ``ml2_port_bindings``
    * ``host`` - binding_host, see port
    * ``profile`` - binding_profile, see port
    * ``vif_details`` - driver-internal extras
 * ``ml2_port_binding_levels``
    * ``driver`` - for each port bound by the driver there has to be a level 0 entry
    * ``host`` - binding_host, again (isn't this a duplicate?)

In our driver-config we have:
 * Hostgroup - maps binding_hosts to vlan pool / physical_network name
    * NOTE: multiple Hostgroups can reference the same physnet_name
 * Host - defines list of interfaces on switches that need to be bound

A network consists of multiple networksegments, which hold the vlan and the physical network in question.
Ports are bound to segments and hold a binding_host as well, which should match a host in our config
(else we cannot bind the port).

So to generate a full config for a network we need to look at the following things:
 * all binding_hosts in a network specify which ports are bound to a network
    * all binding_hosts can be found by querying all ports for a network
    * the networksegment they're bound to carry the vlan id we need to use

Sync Operations
~~~~~~~~~~~~~~~
There are three sync operations the driver is using:
 * hostgroup-network-sync - sync for a single hostgroupin one network on all switches, used on port bind or port delete
 * network-sync - sync all hostgroups for a single network on all switches
 * switch-sync - snyc all networks on a single switch

hostgroup-network-sync bind:
 * get hostgroup of binding_host
 * find (or create) matching segment
 * sync this networksegment to all switches that have interfaces in the hostgroup

hosgroup-network-sync delete:
 * get hostgroup of binding_host
 * check if any ports with the same binding_host remain. if so, stop
 * check if any other binding_hosts are using the same interface. if all interfaces are still in use, stop
    * FIXME: maybe we can check only hosts on the same networksegment?
 * rpc call: remove vlan from all unused interfaces
 * find matching network segment
 * if no host in current network binds this segment, remove it from DB

network-sync:
 * get all binding_hosts for this network
 * get all hostgroups from binding_hosts, generate config with help of segments
 * ...

switch-sync:
 * get all physical_networks that could be on the switch to sync
 * query all networksegments with these physical_networks
 * get all ports bound by the driver for this on these segments
 * use this to get a list of binding hosts to generate the necessary config
 * send to agent, tell it that this is the complete list and other mappings can be cleaned

Agent Design
~~~~~~~~~~~~


Agent Communication
~~~~~~~~~~~~~~~~~~~
Operation: add, remove, replace

For communicating a change to an agent we need to include the following information per switch:
 * switch identifier
 * list of vni mappins
    * operation - add, remove, replace
 * list of local vlans
    * operation - add, remove, replace
    * description (network uuid)
 * list of interfaces + their config
    * vlans
    * vlan translations
    * port-channel id (optional)
    * member-interfaces for port-channel (optional)

Note: For a port-channel all subinterfaces will be overriden with the same config a the moment. An
alternative idea would be to only configure this interface in case of direct-on-fabric stuff, e.g.
native vlans.



Network Syncloop (in Agent)
~~~~~~~~~~~~~~~~~~~~~~~~~~~


Network Scheduling on Borderleafs and ACI Transits
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Both Borderleafs and ACI Transit Switches have a maximum capacity of x VLANS (2000 on Arista, 1750 on ACI).


