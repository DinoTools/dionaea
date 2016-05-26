Configuration
=============

If you want to change the software, it is really important to understand how it works, therefore please take the time to how it works.
:file:`dionaea.cfg` is the main configuration file.
In the example below you can see the default configuration.

.. literalinclude:: ../../conf/dionaea.cfg.in
    :language: ini
    :caption: dionaea.cfg

dionaea
-------

**listen.mode:**

    There are basically three modes how dionaea can bind the services to IP addresses.

    - **getifaddrs** - auto
        This will get a list of all IP addresses of all available interfaces and bind the services to each IP.
        It is also possible to specify a list of interfaces to use by using the :code:`listen.interfaces` perameter.

    - **manual** - your decision
        In this mode you have to specify an additional parameter :code:`listen.addresses`.
        This is a comma separated list of IP addresses dionaea should bind the services to.

    - **nl**, will require a list of interfaces
        You have to specify a comma separated list of interfaces names with the :code:`listen.interfaces` parameter.
        If an IP address is added to an interfaces or removed from an interface dionaea will lunch or stop all services for this IP.

Logging
-------

dionaea has a general application log.
This logs are ment to be used for debugging and to track errors.
It is not recommended to analyse this files to track attacks.

**filename**

    The filename of the logfile.

**levels**

    Only log messages that match the specified log level get logged to the logfile.

**domain**

    Only log messages in a specified domain.


Modules
-------

Only modules specified by the :code:`modules` value in the :code:`dionaea` section are loaded during the start up.

Every module might have its own config section with additional config parameters.
The section name consists of the prefix :code:`module` and the module name sperateted by a dot(:code:`.`).

See the :doc:`module/index` documentation to find more information on how to configure the modules.


Processors
----------



