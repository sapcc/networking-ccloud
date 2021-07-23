*** Settings ***
Documentation     Swift VMs need BGP peering with upstream devices.
...
...               Swift VM uses BGP for dynamic routing with upstream devices. 
...               Usually it peers with 2 upstream devices for redundancy. 
...               
...               Swift VMs should use same next-hop IP addresses within management network for 
...               BGP peering with 2 upstream devices independant of pod.
...               
...               Swift VMs use traceroute with ttl=1 for upstream device IP address discovery 
...               and use discovered IP addresses for their BGP next-hop configuration.
...               
...               BGP peering is used for prefix announcement from Swift VMs to upstream.
...               
...               Swift VMs advertise Kubernetes internal subnets which must not be routed outside 
...               of the fabric. Communication between controlplane VMs and Kubernetes internal subnets 
...               must be possible.
...               
...               Swift VMs advertise Kubernetes external subnets and /32 IP addresses which must
...               be routed outside of the fabric. Connectivity from other SAP networks and all CC+1 regions to
...               Kubernetes external subnets must be possible.
...            
Default Tags      stPod      Controlplane      Swift

*** Test Cases ***

Traceroute to discover 2 next-hops
    Skip    Not implemented

BGP Peering
    Skip    Not implemented
