2. Edit the ``/etc/networking_ccloud/networking_ccloud.conf`` file and complete the following
   actions:

   * In the ``[database]`` section, configure database access:

     .. code-block:: ini

        [database]
        ...
        connection = mysql+pymysql://networking_ccloud:NETWORKING_CCLOUD_DBPASS@controller/networking_ccloud
