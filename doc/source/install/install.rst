.. _install:

Install and configure
~~~~~~~~~~~~~~~~~~~~~

This section describes how to install and configure the
Networking CCloud VXLAN Fabric service, code-named networking_ccloud, on the controller node.

Installation
------------

Install the driver via pip into your system:

   .. code-block:: console

     # pip install https://github.com/sapcc/networking-ccloud/

Neutron Configuration
---------------------

The driver needs to be included in your ``mechanism_drivers``. Make sure that
the driver is configured to be at the beginning of your drivers, else this might
cause problems with the hierarchical portbinding.

   .. code-block:: ini

    [ml2]
    mechanism_drivers = cc-fabric,...

If you use the networking-aci driver, make sure to put this one in front of
cc-fabric for now.

Driver Configuration
--------------------
The configuration is split in two parts:
1. The "oslo config" part, which contains some generic configuration and the path to the driver config
2. The driver config

The driver config contains a complete description of your infrastructure: All switches, their
switchgroups and the bindinghost <--> hostgroup mapping, amongst other stuff. If you have a NetBox instance
you can use `cc-netbox-config-gen` to generate a driver config.

Agent Configuration
-------------------
The switch agent takes care of all device configuration. You will need to
start one agent per switch vendor. The agent takes the same configuration files
as the ml2 driver, so make sure to supply it with the same driver config as the
ml2 driver. Note, that the agent will only use the driver config for getting
access to the switches, all other information is ignored.

Currently available agents are:
 * ``cc-arista-switch-agent``
 * ``cc-nxos-switch-agent``
