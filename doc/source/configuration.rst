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

**download.dir**

    Global download directory used by some :doc:`ihandlers <ihandler/index>`.

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

**modules**

    Comma separated list of :doc:`modules <module/index>`.

**processors**

    Comma separated list of :doc:`processors <processor/index>`.

**ssl.default.c**

    Two letter id of the Country.

**ssl.default.cn**

    The Common Name/domain name of the generated SSL/TLS certificate.

**ssl.default.o**

    The Organization name.

**ssl.default.ou**

    The name of the Organizational Unit.

Logging
-------

dionaea has a general application log.
This logs are ment to be used for debugging and to track errors.
It is not recommended to analyse this files to track attacks.

**filename**

    The filename of the logfile.

**levels**

    Only log messages that match the specified log level get logged to the logfile.

    Available log levels:

    * debug
    * info
    * warning
    * error
    * critical

    * all = Special log level including all log levels

    Examples:

    .. code-blocK:: ini
        :caption: Log only messages with level warning and error

        errors.levels=warning,error

    .. code-blocK:: ini
        :caption: Log all log messages but exclude messages with log level debug

        errors.levels=all,-debug

**domain**

    Only log messages in a specified domain.


Modules
-------

Only modules specified by the :code:`modules` value in the :code:`dionaea` section are loaded during the start up.

Every module might have its own config section with additional config parameters.
The section name consists of the prefix :code:`module` and the module name speratated by a dot(:code:`.`).

See the :doc:`module/index` documentation to find more information on how to configure the modules.


Processors
----------

The specified processors will be used as an entry point in the processing pipeline.
In most cases the initial processor will be a :code:`filter processor <processor/filter>`.
The next processor in the pipeline is specified by the :code:`next` parameter.

See the :doc:`processor/index` documentation to find more information on how to configure the processors.
