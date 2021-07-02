# Avocado on Fabric
The Avocado project for ACI defines a way to use parts of a virtualization cluster as baremetal and vice versa.
It also allows us to deploy hypervisors and other machinery via Ironic as baremetal boxes.

Avocado defines two modes:
 * infra mode
    * ports are bound together with all other ports in hostgroup
    * ports have access to management networks (e.g. vlan 100 - mgmt)
 * baremetal mode
    * port can be bound on its own
    * no access to management networks
    * portchannel can be assembled / disassembled at will (via admin API)
    * OpenStack trunk extension available

## Normal Baremetal Port Binding
Baremetal boxes expect their default ports to be available untagged.

Arista leaf config:
```
! default vlan X, int vxlan1 stuff
!
! for each interface belonging to the hostgroup
interface $eth_x
    switchport mode trunk
    switchport trunk allowed vlan $vlan_bb # only add it...
    switchport trunk native vlan $vlan_bb
```

## Trunk extension
In node baremetal mode if the user binds a network to a server via trunk subport with vlan id `$vlan_user`.

Arista leaf config:
```
vlan $vlan_bb
!
interface vxlan1
    vxlan vlan $vlan_bb vni $vni_net_a
!
! for each interface belonging to the hostgroup
interface $eth_x
    switchport mode trunk
    vlan translation $vlan_user $vlan_bb
    switchport allowed vlan ...

```

NXOS leaf config:
```

```

## Port-Channel
