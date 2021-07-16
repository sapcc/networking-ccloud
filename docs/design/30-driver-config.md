# Driver Config
Based on everything the driver needs to do we can now roughly define what the driver needs to know about the
infrastructure, i.e. what needs to be in its configuration / DB. In the beginning most information will be part of the
configuration file, but for everything that needs to be dynamic (Avocado host-mode, lending out servers to other BBs)
will need to be moved to the DB and managed via an extra In-Driver API command.

Rough contents:
 * Hostgroups
     * Relationship between openstack hosts (nova-compute-bb123, asr1k-agent-01) and switchports
 * VLAN-Pools management
 * ...

## Hostgroups
Hostgroups are the base building block for describing the infra.
