Configuration
=============

If you want to change the software, it is really important to understand how it works, therefore please take the time to how it works.
:file:`dionaea.cfg` is the main configuration file.

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



