*** Settings ***
Documentation     Controlplane VMs need BGP peering with upstream devices.
...
...               Controlplane VM uses iBGP for dynamic routing with upstream devices. 
...               Usually it peers with 2 upstream devices for redundancy. 
...               
...               Controlplane VMs must be able to discover their BGP peers.
...               
...               BGP peering is used for prefix announcement from Controlplane VMs to upstream.
...               
...               Controlplane VMs advertise Kubernetes internal subnets which MUST NOT be routed outside 
...               of the fabric. Communication between controlplane VMs and Kubernetes internal subnets 
...               must be possible.
...               
...               Controlplane VMs advertise Kubernetes external subnets and /32 IP addresses which MUST
...               be routed outside of the fabric. Connectivity from other SAP networks and all CC+1 regions to
...               Kubernetes external subnets MUST be possible.
...               
...               Community tagging of prefixes by Controlplane VMs is an option.
...               
Default Tags      aPod      Controlplane

*** Test Cases ***

Traceroute to discover 2 next-hops
    Skip    Not implemented

BGP Peering
    Skip    Not implemented
