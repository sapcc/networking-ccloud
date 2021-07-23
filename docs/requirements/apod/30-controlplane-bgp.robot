*** Settings ***
Documentation     Controlplane VMs need BGP peering with upstream devices.
...
...               Controlplane VM uses BGP for dynamic routing with upstream devices. 
...               Usually it peers with 2 upstream devices for redundancy. 
...               
...               Controlplane VMs should use same next-hop IP addresses within management network for 
...               BGP peering with 2 upstream devices independant of pod.
...               
...               Controlplane VMs use traceroute with ttl=1 for upstream device IP address discovery 
...               and use discovered IP addresses for their BGP next-hop configuration.
...               
...               BGP peering is used for prefix announcement from Controlplane VMs to upstream.
...               
...               Controlplane VMs advertise Kubernetes internal subnets which must not be routed outside 
...               of the fabric. Communication between controlplane VMs and Kubernetes internal subnets 
...               must be possible.
...               
...               Controlplane VMs advertise Kubernetes external subnets and /32 IP addresses which must
...               be routed outside of the fabric. Connectivity from other SAP networks and all CC+1 regions to
...               Kubernetes external subnets must be possible.
...               
Default Tags      aPod      Controlplane

*** Test Cases ***

Traceroute to discover 2 next-hops
    Skip    Not implemented

BGP Peering
    Skip    Not implemented
