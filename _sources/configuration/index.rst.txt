=============
Configuration
=============

The driver configuration consists of 2 configs. `Oslo Config`_ and `Driver Config`_. `Oslo Config`` focusses more around the runtime of the driver while `Driver Config`` focusses around the topology the driver manages.
Because it would be cumbersome to generate a large topology's `Driver Config` by hand we generate it from netbox using `Netbox Config Generator`_. In this section we will document how these configs are structured and what prerequisites `Netbox Config Generator` expects. 

.. _`Oslo Config`: https://github.com/sapcc/networking-ccloud/blob/HEAD/networking_ccloud/common/config/config_oslo.py
.. _`Driver Config`: https://github.com/sapcc/networking-ccloud/blob/HEAD/networking_ccloud/common/config/config_driver.py
.. _`Netbox Config Generator`: https://github.com/sapcc/networking-ccloud/blob/HEAD/networking_ccloud/tools/netbox_config_gen.py

.. toctree::
    :maxdepth: 2

    config-gen.rst
    config-driver.rst
    config-oslo.rst
