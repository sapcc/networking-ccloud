# Availability Zones
An OpenStack Availability Zones (AZs) is a logical partition of a region. An AZ often represents a single independant
DC. OpenStack resources like networks and routers can live in multiple AZs, but can - with AZ hints - be scoped to a
single AZ.

## Spanning Networks Across AZs
In the new fabric we will be using Border Gateways (BGWs) to span an l2 network across multiple AZs. Although we can
have multiple BGW pairss per AZ we will generally have only one. All networks that span AZs will need to be configured
on each BGW of the AZs where it should be present. AZs that do not want a network present that is present in other AZs
just don't import its RT.

We have a rough limit of 2500 vlans per BGW pair, due to a platform limitation on our Aristas. If we need to grow
past this number of networks we will need to add another BGW pair and implement network-BGW scheduling inside the
driver (so we most likely will need to go with BGW scheduling from the start).

Networks will be deployed on demand

Note: On the BGW we can also share single subnets of a l3 network
FIXME: VRFs on bordergateway - explanation why do we need it
 * vxlan vrf fooo only for external networks

Internal networks:
```
interface vxlan1
    vxlan vlan <tenant_vlan_id> vni <tenant_l2vni_id>
!
router bgp <as_number>
    vlan <tenant_vlan_id>
        rd <loopback_1_ip>:<tenant_l2vni_id>
        route-target both <tenant_l2vni_id>:<tenant_l2vni_id>
        redistribute learned
```

External networks:
```
interface vxlan1
    vxlan vlan <tenant_vlan_id> vni <tenant_l2vni_id>
    vxlan vrf <tenant_vrf_name> vni <tenant_l3vni_id>
!
router bgp <as_number>
    vlan <tenant_vlan_id>
        rd <loopback_1_ip>:<tenant_l2vni_id>
        route-target both <tenant_l2vni_id>:<tenant_l2vni_id>
        redistribute learned

    vrf <tenant_vrf_name>
        router-id <loopback_0_ip>
        rd <loopback_1_ip>:<tenant_l3vni_id>
        route-target import evpn <tenant_l3vni_id>:<tenant_l3vni_id>
        route-target export evpn <tenant_l3vni_id>:<tenant_l3vni_id>
```

`tenant_vrf_name`: Each external network is associated with an address scope (via subnet -> subnetpool -> address
                   scope). The address scope name needs then to be mapped to a VRF (e.g. cc-public to CC-CLOUD01).
                   This mapping will be done in driver config for now. CC-CLOUD01 will be associated with an l3-vni
                   as well.

The `vrf <tenant_vrf_name>` part and `vxlan vrf ...` part could be preprovisioned.

## AZ Awareness
Some network resources can be AZ aware
FIXME: include assumptions from CCM-19460
