*** Settings ***
Documentation     aPod node LAG1 connectivity.
...
...               LAG1 currently consists of two physical interfaces connected to 2 upstream devices.
...               Link aggregation is configured using LACP protocol.
...               
...               Link aggregation must be configured in LACP Active.
...               Link aggregation must suspended individual ports.
...               Link aggregation must use Fast LACP timer.
...               
...               aPod node LAG1 need connectivity to following networks:
...               - Controlplane management network (tagged), Netbox description: 
...                 Region wide peering network between CP nodes and ACI fabric.
...               - Controlplane sync network (tagged)
...               - aPOD Management Network (tagged), site-specific
...               - aPOD vMotion Network (tagged), site-specific
...               - aPOD VM Network (tagged), site-specific
...               
Library           SSHLibrary
