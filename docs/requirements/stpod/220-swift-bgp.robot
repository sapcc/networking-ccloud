*** Settings ***
Documentation     Swift VMs need BGP peering with upstream devices.
...
...               Refer to Controlplane VM BGP requirements file.
...            
Default Tags      stPod      Controlplane      Swift

*** Test Cases ***

Traceroute to discover 2 next-hops
    Skip    Not implemented

BGP Peering
    Skip    Not implemented
