*** Settings ***
Documentation     aPod node onboard L1 connectivity.
...
...               Interface should become active without delays (spanning-tree port type edge)
...               
...               aPod node L1 need connectivity to following networks:
...               - aPOD Management Network (access), site-specific
...                 Network role: CC Management
...               - aPOD VM Network (tagged), site-specific
...                 Network role: CC Management
...               - PX Service 1 Plane 1 VLAN (tagged)
...               - PX Service 1 Plane 2 VLAN (tagged)
...               - PX Service 1 Plane 3 VLAN (tagged)
...               
Default Tags      aPod      ESX     VMware

*** Test Cases ***

L1 connectivity
    Skip    Not implemented
