*** Settings ***
Documentation     Swift node LAG1 connectivity.
...
...               LAG1 currently consists of two or four physical interfaces connected to 2 upstream devices.
...               The physical interfaces are bound to LAG1 in Netbox.
...               Link aggregation is configured using LACP protocol.
...               
...               Link aggregation must be configured in LACP Active.
...               Link aggregation must suspended individual ports.
...               Link aggregation must use Fast LACP timer.
...               
...               Swift node LAG1 need connectivity to following networks:
...               - Controlplane transit network (tagged) 
...                 Network role: CC Kubernetes Transit
...               - Controlplane sync vlan (tagged)
...                 VLAN role: tag to be created in Netbox
...               - aPOD Management Network (tagged), site-specific
...                 Network role: CC Management
...               - aPOD vMotion Network (tagged), site-specific
...                 Network role: CC vMotion
...               - aPOD VM Network (tagged), site-specific
...                 Network role: CC Management
...               
Default Tags      stPod      ESX     VMware

*** Test Cases ***

LAG1 connectivity
    Skip    Not implemented
