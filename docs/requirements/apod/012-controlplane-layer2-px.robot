*** Settings ***
Documentation     Controlplane VMs need connectivity to PX Domains (1 and 2).
...
...               Controlplane VMs should be able to communicate within this layer2 domain without 
...               MAC address learning/resolution restrictions.
...               
Default Tags      aPod      Controlplane

*** Test Cases ***

PX network ARP resolution
    Skip    Not implemented
