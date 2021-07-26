*** Settings ***
Documentation     aPod node LAG0 connectivity.
...
...               LAG0 currently consists of two physical interfaces connected to 2 upstream devices.
...               The physical interfaces are bound to LAG0 in Netbox.
...               Link aggregation is configured using LACP protocol.
...               
...               Link aggregation must be configured in LACP Active.
...               Link aggregation must not suspend individual ports (Ironic boot).
...               
...               aPod node LAG0 need connectivity to Openstack tenant networks and should be 
...               able to set a VLAN id of any Openstack tenant network segment.
...               
...               Switch side of this LAG is driver controlled.
...               
Default Tags      aPod      ESX

*** Test Cases ***

LAG0 connectivity
    Skip    Not implemented
