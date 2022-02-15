Generator Input
~~~~~~~~~~~~~~~

The driver configuration is generated based on input from external toooling (Netbox) and the following conventions.

************
Leaf Pair
************

All EVPN fabric members will be of the following Netbox roles:

* **EVPN Spine**: Used for all spine switches, not configured by driver
* **EVPN Border Gateway**: Used for all gateways interconnecting CC AZ's in a multi AZ fabric
* **EVPN Leaf**: Used for all leaf switches in the EVPN fabric

Further more specific leaf functions will be identified by adding tags to the leafs.

Uniq Pair ID
#############
Each leaf pair (MLAG/VPC) requires a fabric uniq 4 digit ID (XYZZn) with an a/b identifier for leaf in group per leaf pair used to generate device specifig configuration settings (ASN etc.)

* X: CCloud AZ 1=a, 2=b, etc.
* Y: EVPN Spine POD in AZ 1,2,3... etc.
* ZZ: Two digit uniq leaf pair identifier 01-99
* n: a=fist leaf in pair, b=second leaf in pair

Netbox Query:
::
    Role: EVPN Leaf
    Name: .*(\d\d\d\d)([a-b]).* #\1=leaf_id \2=leaf_a_b

CCloud Pod leafs
################
All CCloud pod types will be tagged to the leaf to identify sub-role:

Netbox Query:
::
    Role: EVPN Leaf
    Name: .*(\d\d\d\d)([a-b]).* #\1=leaf_id \2=leaf_a_b
    Tag: CC-APOD|CC-BPOD|CC-NETPOD|CC-STPOD|CC-VPOD

CND EVPN leaf types:
####################
The driver needs to identify certain non-pod leaf pairs to 
push tenant configuration:

ACI transit leaf, required to extend tenant networks to leagcy ACI fabric
 
Netbox Query:
::
    Role: EVPN Leaf
    Name: .*(\d\d\d\d)([a-b]).* #\1=leaf_id \2=leaf_a_b
    Tag: CND-EVPN-ACI-TRANSIT

EVPN Border Leaf, required to set summarization/aggregation for tenant subnet pools.

Netbox Query:
::
    Role: EVPN Leaf
    Name: .*(\d\d\d\d)([a-b]).* #\1=leaf_id \2=leaf_a_b
    Tag: CND-EVPN-BORDER-LEAF

