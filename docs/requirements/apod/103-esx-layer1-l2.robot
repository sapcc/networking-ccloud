*** Settings ***
Documentation     aPod node onboard L2 connectivity.
...
...               Interface should become active without delays (spanning-tree port type edge)
...               
...               aPod node L2 need connectivity to following networks:
...               - PX Service 2 Plane 1 Plane (tagged)
...               - PX Service 2 Plane 2 Plane (tagged)
...               - PX Service 2 Plane 3 Plane (tagged)
...               
Default Tags      aPod      ESX     VMware

*** Test Cases ***

L2 connectivity
    Skip    Not implemented
