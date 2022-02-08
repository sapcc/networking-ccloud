Switch Config
~~~~~~~~~~~~~
This part describes the on-device config for all feature and vendor combinations.


Normal VM portbinding
---------------------
* VXLAN <-> VLAN mapping
* Add a VLAN to ports in questions

Baremetal-on-Fabric portbinding
-------------------------------
* VXLAN <-> VLAN mapping
* Add a VLAN to ports in question
* Set it as native vlan

Baremetal-on-Fabric trunk
-------------------------
...basically same as normal VM portbinding, but port in OpenStack looks different


External network config + l3 gateway
------------------------------------
TBD

Management Networks
-------------------
TBD, config is also not yet specified for this

Host lending
------------
Mass VLAN translations in original home of server.
FIXME: Scalability considerations

ACI transit connection
----------------------
The Transit (or ACI Transit) is used to connect the fabric to another ml2
top level driver, like our networking-arista driver. The ACI driver and this
driver (networking-ccloud) both share responsibility for the top hierarchy.
For this to work they need to be interconnected. This means that whenever
an OpenStack network should be present both on ACI and networking-ccloud side
it needs a transit between these two fabrics.

The transit is done by having two switches connected with each other, one on
each side and having the drivers coordinate on the VLANs used there. networking-ccloud
will create the necessary segment, as it is on top of the hierarchy.

Other drivers will have to be notified of this change, options are:
 * having an own signal in bind_port
 * use `(create|update|delete)_port_postcommit` (or something alike)

In config (and NetBox) each Transit will have a list of AZs associated with it
that it feels respnosible for. Whenever a network is either stretched across
AZs or is present in at least one AZ and on the "other side" (e.g. ACI) the
driver will schedule the network to an ACI transit for each AZ it is in.
One Transit can be responsible for multiple AZs. If a Transit is in a
different AZ than other portbindings, BGWs will be configured for inter-AZ
communication inside the fabric. When the Transit is no longer needed (e.g.
when the last port in one AZ is removed and no other AZ is using this transit
then the scheduling of this (AZ, Transit, Network) and its respective segment / VLAN
allocation will be removed.

How scheduling / binding roughly works:
 * find AZs of network
 * make sure every (network / AZ) combination has a Transit assigned (if available)
 * if new transit is scheduled
    * allocate segment
    * schedule / handle BGWs (if Transit is in different zone)
    * add transit to binding hosts? (FIXME)
    * bind segment
    * notify others

Note: Scheduling of BGWs is something we need to take care of here as well. Not every
AZ has to have a Transit. In some cases Tranits of other AZs take over. If the Transit
is the first binding in a new AZ we need to schedule the BGW for this AZ and then, again,
a Transit for this AZ. We probably should make sure this is the same Transit and enforce
via config that a Transit has to serve at least its own AZ.


 * [0,n] transit pairs per AZ
 * 1750 vlans per transit
 * transit in one AZ needs to be bound when port present in AZ x and
    * port in ACI
    * port in AZ y != x
 * each AZ needs a transit that handles its traffic
    * each transit has one or more AZs it's responsible for
    * driver will schedule each AZ the network is in onto a transit

Inter-AZ communication / BorderGateWays (BGWs)
----------------------------------------------
Configure something on the borderleafs, devicerole foo.
