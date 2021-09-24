Prerequisites
-------------

Before you install and configure the Networking CCloud VXLAN Fabric service,
you must create a database, service credentials, and API endpoints.

#. To create the database, complete these steps:

   * Use the database access client to connect to the database
     server as the ``root`` user:

     .. code-block:: console

        $ mysql -u root -p

   * Create the ``networking_ccloud`` database:

     .. code-block:: none

        CREATE DATABASE networking_ccloud;

   * Grant proper access to the ``networking_ccloud`` database:

     .. code-block:: none

        GRANT ALL PRIVILEGES ON networking_ccloud.* TO 'networking_ccloud'@'localhost' \
          IDENTIFIED BY 'NETWORKING_CCLOUD_DBPASS';
        GRANT ALL PRIVILEGES ON networking_ccloud.* TO 'networking_ccloud'@'%' \
          IDENTIFIED BY 'NETWORKING_CCLOUD_DBPASS';

     Replace ``NETWORKING_CCLOUD_DBPASS`` with a suitable password.

   * Exit the database access client.

     .. code-block:: none

        exit;

#. Source the ``admin`` credentials to gain access to
   admin-only CLI commands:

   .. code-block:: console

      $ . admin-openrc

#. To create the service credentials, complete these steps:

   * Create the ``networking_ccloud`` user:

     .. code-block:: console

        $ openstack user create --domain default --password-prompt networking_ccloud

   * Add the ``admin`` role to the ``networking_ccloud`` user:

     .. code-block:: console

        $ openstack role add --project service --user networking_ccloud admin

   * Create the networking_ccloud service entities:

     .. code-block:: console

        $ openstack service create --name networking_ccloud --description "Networking CCloud VXLAN Fabric" networking ccloud vxlan fabric

#. Create the Networking CCloud VXLAN Fabric service API endpoints:

   .. code-block:: console

      $ openstack endpoint create --region RegionOne \
        networking ccloud vxlan fabric public http://controller:XXXX/vY/%\(tenant_id\)s
      $ openstack endpoint create --region RegionOne \
        networking ccloud vxlan fabric internal http://controller:XXXX/vY/%\(tenant_id\)s
      $ openstack endpoint create --region RegionOne \
        networking ccloud vxlan fabric admin http://controller:XXXX/vY/%\(tenant_id\)s
