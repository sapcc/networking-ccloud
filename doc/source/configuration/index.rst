=============
Configuration
=============

The driver configuration consists of 2 configs. `Oslo Config`_ and `Driver Config`_. `Oslo Config`` focusses more around the runtime of the driver while `Driver Config`` focusses around the topology the driver manages.
Because it would be cumbersome to generate a large topology's `Driver Config` by hand we generate it from netbox using `netbox_config_gen`_. In this section we will document how these configs are structured and what prerequisites `netbox_config_gen` expects. 

.. _`Oslo Config`: https://github.com/sapcc/networking-ccloud/blob/HEAD/networking_ccloud/common/config/config_oslo.py
.. _`Driver Config`: https://github.com/sapcc/networking-ccloud/blob/HEAD/networking_ccloud/common/config/config_driver.py
.. _`netbox_config_gen`: https://github.com/sapcc/networking-ccloud/blob/HEAD/networking_ccloud/tools/netbox_config_gen.py

.. toctree::
    :maxdepth: 2

    config-oslo.rst
    config-driver.rst
    config-input.rst
