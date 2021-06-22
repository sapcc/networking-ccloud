# Neutron address-scope

Address Scopes in CCloud define the relationship of a subnet (via the indirection of subnet -> subnet poll -> address scope) to a given VRF. The scope of the subnet needs also to be taken into account.


### Example
```javascript
{
    "address_scopes": [
        {
            "name": "neo-public",
            "tenant_id": "a7a7fa10fd7a4c80acb7e4b224480495",
            "ip_version": 6,
            "shared": false,
            "project_id": "a7a7fa10fd7a4c80acb7e4b224480495",
            "id": "3b189848-58bb-4499-abc2-8df170a6a8ae"
        },
        {
            "name": "neo-public",
            "tenant_id": "a7a7fa10fd7a4c80acb7e4b224480495",
            "ip_version": 4,
            "shared": false,
            "project_id": "a7a7fa10fd7a4c80acb7e4b224480495",
            "id": "4143da3e-d2a7-4077-ba80-215ecfd016d7"
        }
    ]
}
```

### Driver Config
```
[global]
base-asn = 65130 # Example QA-DE-1
[vrf-mapping]
cc-cloud01 = 3b189848-58bb-4499-abc2-8df170a6a8ae, 4143da3e-d2a7-4077-ba80-215ecfd016d7

```

### Object Scope and Relation
* subnet to address-scope: n:1
* address-scope to vrf: n:1
* region wide subnet in 4143da3e-d2a7-4077-ba80-215ecfd016d7 -> VRF CC-CLOUD01
* az-local(a) subnet in 4143da3e-d2a7-4077-ba80-215ecfd016d7 -> VRF CC-CLOUD01-A

### Conventions
#### Route-Targets
Fabric originated subnets

|            | regional         | a                 | b                 | c                 | d                 |
|------------|------------------|-------------------|-------------------|-------------------|-------------------|
| CC-CLOUD01 | $base-asn$.0:101 | $base-asn$.1:1101 | $base-asn$.2:2101 | $base-asn$.3:3101 | $base-asn$.4:4101 |
| ...        | ...              | ...               | ...               | ...               | ...               |
| CC-CLOUD50 | $base-asn$.0:150 | $base-asn$.1:1150 | $base-asn$.2:2150 | $base-asn$.3:3150 | $base-asn$.4:4150 |
| CC-MGMT    | $base-asn$.0:900 | $base-asn$.1:1900 | $base-asn$.2:2900 | $base-asn$.1:3900 | $base-asn$.4:4900 |

Core originated subnets

## On Device Config

### Device Scale

1. max VRF
  * eOS
  * NX-OS 

Example based on Leafs in QA-DE-1a, assuming qa-de-1 has AZ's a,b,d

### Generic Pod Local Leaf

##### eOS
leaf pair ID 1120 leaf a

```
vlan 101
   name CC-CLOUD01-MLAG
   
vlan 1101 
   name CC-CLOUD01-A-MLAG

interface 101
  ip address 169.254.255.254/31
  vrf CC-CLOUD01
  no autostate
  mtu 9000

interface 1101
  ip address 169.254.255.254/31
  vrf CC-CLOUD01-A
  no autostate
  mtu 9000

router bgp 
   vrf CC-CLOUD01
      router-id 1.1.20.1
      rd 65130.1120:101
      route-target import evpn 65130.0:101
      route-target export evpn 65130.0:101
      route-target import evpn 65130.1:1101
      route-target import evpn 65130.2:2101
      route-target import evpn 65130.3:3101
      !
      neighbor 169.254.255.255/31 peer group PG-MLAG-OVERLAY
      
   vrf CC-CLOUD01-A
      router-id 1.1.20.1
      rd 65130.1120:1101
      route-target import evpn 65130.0:101
      route-target export evpn 65130.0:101
      route-target import evpn 65130.1:1101
      !
      neighbor 169.254.255.255/31 peer group PG-MLAG-OVERLAY


```
##### NX-OS
```

```

### Border Gateway

##### eOS
```

```
##### NX-OS
```

```

### Border Leaf

##### eOS
```

```
##### NX-OS
```

```

### ACI Transit Leaf
##### eOS
```

```
##### NX-OS
```

```

## Test Cases