*** Settings ***
Documentation     Controlplane VMs need connectivity to each other for sync purposes.
...
...               Sync network should be a shared layer2 domain across controlplane VMs.
...               Controlplane VMs should be able to communicate within this layer2 domain without 
...               MAC address learning/resolution restrictions.
...               
...               Controlplane and Swift VMs share the same Controlplane sync network.
...               
Default Tags      aPod      Controlplane

*** Test Cases ***

Sync network ARP resolution
    Skip    Not implemented
