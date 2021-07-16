# Ports and Port Bindings
An OpenStack port represents a connection between a device (VM-nic, baremetal server-nic, loadbalancer, router, ...)
and an OpenStack network.

## Port Binding Process
1. Port binding will arrive at `networking-ccloud` aka The Driver
2. The Driver will look at the `host` associated to the port and will decide to which hostgroup it belongs
    * for most ports this is `binding_host_id`
    * for baremetal this is part of the `binding_profile`
    * a hostgroup is generally associated with one leafpair
3. The Driver will create a network segment (or already have one) in its DB
    * VLAN id will be chosen from a leaf-pair-local VLAN pool
4. The Driver will call `continue_binding()` and hand over control to the next driver
5. IF this is for a port/device connected directly to the fabric (`direct_mode`) The Driver will handle final portbinding
    * for baremetal it will provide trunk ports


Assuming `$bb` has has been bound to `$net_a` with `$vlan_bb`, while `$vni_net_a`
Config on Arista Leaf:
```
vlan $vlan_bb
!
interface vxlan1
    --- vxlan1 default config omitted here
    vxlan vlan $vlan_bb vni $vni_net_a
    vxlan vrf $L2_VRF vni $L2_VRF_VNI   # in aci this is currently aci-l2-vrf
!
! for each interface part of this hostgroup
interface $eth_x
    switchport mode trunk
    switchport trunk allowed vlan add $vlan_bb  # only add the vlan
!
bgp $asn_leaf_bb
    vlan $vlan_bb
        rd $leaf_loopback_0
        route-target both $vni_net_a:$vni_net_a
        redistribute learned
        redistribute connected
```
 * We need to know or control `$leaf_loopback_0` per leaf
 * we need to make sure for new interfaces that they have a `switchport trunk allowed vlan` list (by default vlans all are allowed)


Config on NXOS leaf:
```

```


## Baremetal on Fabric
Baremetal servers are in most cases directly on dedicated Arista switches which will become part of our fabric.
With this integration they will be direct-on-fabric devices. This case is similar to the Avocado-Baremetal case
(see 11-avocado.md).

Arista leaf config:
```

```

## Trunk Ports
The Driver will only do special handling for trunk ports that are handled by The Driver itself, e.g. anything The Driver
does the final binding for.
