*** Settings ***
Documentation     aPod node LAG0 connectivity.
...
...               LAG0 currently consists of two physical interfaces connected to 2 upstream devices.
...               Link aggregation is configured using LACP protocol.
...               
...               Link aggregation must be configured in LACP Active.
...               Link aggregation must not suspended individual ports (Ironic boot).
...               
...               aPod node LAG0 need connectivity to Openstack tenant networks and should be 
...               able to set a VLAN id of any Openstack tenant network segment.
...               
Default Tags      aPod      ESX

*** Test Cases ***

LAG0 connectivity
    Skip    Not implemented
