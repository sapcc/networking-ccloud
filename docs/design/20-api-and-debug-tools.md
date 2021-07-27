# In-Driver API for Debugging and Maintenance
The In-Driver API is an API directly inside the driver using OpenStack authentication and other OpenStack facilities to
provide debug information and driver commands (sync a router, switch host-mode).


## Network-Related Actions

### Current Network Status
Show status of a given network, pulled from OpenStack DB, enrichted with driver-config knowledge. This will include
hostgroups bound to the network, on which leaf switches the network should be bound, etc. This is basically the same
data the driver hands out to its agents to sync a network.

### Network Diff
Get the current network state and ask each agent for a diff. The agent will use the sync data to generate device config,
pull the current state off of the device and return a diff between those two. This will be returned to the API-user in a
per-device dictionary.

### Network Sync
Tell the driver to reapply the network config to all leaf switches the network should be on. We MAY want to check other
switches for leftover config (check that the VNI is not configured on any device it should not be on), though this could
also be handled by a separate per-device cleanup loop.

## Switch / Leafpair Related Actions
Currently in brainstorming phase:
 * test connection
    * dump version and uptime of all connected devices
 * resync all networks on a device

## Driver Related Actions
 * show syncloop status
    * pause syncloop
 * switch hostgroup state for avocado
