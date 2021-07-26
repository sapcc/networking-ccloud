*** Settings ***
Documentation     Swift VMs need connectivity to each other for sync purposes.
...
...               Refer to Controlplane VM sync VLAN requirements file.
...               
Default Tags      stPod      Controlplane      Swift

*** Test Cases ***

Sync network ARP resolution
    Skip    Not implemented
