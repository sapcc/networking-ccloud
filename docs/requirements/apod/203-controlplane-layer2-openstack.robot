*** Settings ***
Documentation     Controlplane VMs need connectivity to Openstack tenant networks.
...
...               Controlplane VMs should be able to communicate with these layer2 domains without 
...               MAC address learning/resolution restrictions.
...               
...               Controlplane VMs should be able to set a VLAN id of any Openstack tenant network segment.
...               
Default Tags      aPod      Controlplane

*** Test Cases ***

Openstack network ARP resolution
    Skip    Not implemented
