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
TBD


Inter-AZ communication
----------------------
Configure something on the borderleafs, devicerole foo.
