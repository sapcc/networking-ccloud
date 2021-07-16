# ACI <--> VXLAN Fabric Interconnect
To connect the ACI fabric with our new fabric we will have one (or more) leafs on each side to do a l2 handover via
VLANs.
FIXME: indepth description

 * vlan handover
 * same vlan on aci transit and arista transit
 * hard limit of 1750 vlans on aci side
    * we MIGHT need to support having two transits


 * l3 gateway transition: might have to carry mac address over
    * at beginning: all gateways on ACI
    * at the end: all gateways on fabric
