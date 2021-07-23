*** Settings ***
Documentation     Swift VMs need connectivity to each other for sync purposes.
...
...               Sync network should be a shared layer2 domain across controlplane VMs.
...               Swift VMs should be able to communicate within this layer2 domain without 
...               MAC address learning/resolution restrictions.
...               
...               Controlplane and Swift VMs share the same Controlplane sync network.
...               
Default Tags      stPod      Controlplane      Swift

*** Test Cases ***

Sync network ARP resolution
    Skip    Not implemented
