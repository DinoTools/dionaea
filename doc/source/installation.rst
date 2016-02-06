Installation
============

At the time of writing the best choice to install dionaea on a server is to use Ubuntu 14.04.

Arch Linux
----------

Packages for dionaea are available from the Arch User Repository (AUR).
Use a package manager like yaourt that can handle and install packages from the AUR.

Before you start install the required build tools.

.. code-block:: console

    $ yaourt -S base-devel

After the requirements have been installed successfully you can install dionaea.
This will checkout the latest sources from the git repository, run the build process and install the package.

.. code-block:: console

    $ yaourt -S dionaea-git

After the installation has been completed you may want to edit the config file /etc/dionaea/dionaea.conf.
If everything looks fine the dionaea service can bee started by using the following command.

.. code-block:: console

    $ sudo systemctl start dionaea

The log files and everything captured can be found in the directory /var/lib/dionaea/.

Ubuntu 14.04
------------

Package based
^^^^^^^^^^^^^

Nightly packages are provided in a Personal Package Archive (PPA).
Before you start you should update all packages to get the latest security updates.

.. code-block:: console

    $ sudo apt-get update
    $ sudo apt-get dist-upgrade


First of all install the tools to easily manage PPA resources.

.. code-block:: console

    $ sudo apt-get install software-properties-common

After the required tools have been installed you can add the PPA and update the package cache.

.. code-block:: console

    $ sudo add-apt-repository ppa:honeynet/nightly
    $ sudo apt-get update

If everything worked without any errors you should be able to install the dionaea package.


.. code-block:: console

    $ sudo apt-get install dionaea

After the installation has been completed you may want to edit the config file /etc/dionaea/dionaea.conf.
If everything looks fine the dionaea service can bee started by using the following command.

.. code-block:: console

    $ sudo service dionaea start

The log files can be found in the directory /var/log/dionaea/ and everything else captured and logged by the honeypot can be found in the directory /var/lib/dionaea/.
