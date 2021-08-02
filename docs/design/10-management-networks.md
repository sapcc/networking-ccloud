# Management Networks
Most leaf pairs will have management networks living on them, which shall be used by the hypervisor solution in a
building block for whatever they are needed (VM migration, management communication, storage, console, ...).
Originally these networks were seen as local to a leaf pair, but as we also want to be able to put servers from another
leaf pair into these networks (e.g. in case of maintenance or hardware failure), we cannot treat these networks as
local to a leaf pair.

Between members of this network we need to have VLAN consistency (as we do when "lending a host" to another bb).
This means each port in a management network will get it as the same VLAN (i.e. mgmt --> 100). It will still need
to be represented with its own VNI inside the fabric.

Management networks are L3, so they also need to have a gateway.
