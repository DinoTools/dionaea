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

From Source
^^^^^^^^^^^

Install required build dependencies before configuring and building dionaea.

.. code-block:: console

    $ sudo apt-get install \
        autoconf \
        automake \
        build-essential \
        check \
        cython3 \
        libcurl4-openssl-dev \
        libemu-dev \
        libev-dev \
        libglib2.0-dev \
        libloudmouth1-dev \
        libnetfilter-queue-dev \
        libnl-dev \
        libpcap-dev \
        libssl-dev \
        libtool \
        libudns-dev \
        python3 \
        python3-dev \
        python3-yaml

After all dependencies have been installed successfully run :code:`autreconf` to build or rebuild the build scripts.

.. code-block:: console

    autoreconf -vi

Run :code:`configure` to configure the build scripts.

.. code-block:: console

    ./configure \
        --disable-werror \
        --prefix=/opt/dionaea \
        --with-python=/usr/bin/python3 \
        --with-cython-dir=/usr/bin \
        --with-ev-include=/usr/include \
        --with-ev-lib=/usr/lib \
        --with-emu-lib=/usr/lib/libemu \
        --with-emu-include=/usr/include \
        --with-nl-include=/usr/include \
        --with-nl-lib=/usr/lib


Now you should be able to run :code:`make` to build and run :code:`make install` to install the honeypot.

.. code-block:: console

    make
    sudo make install


3rd-party packages
------------------

The packages below are 3rd party provided, which is appreciated.
If you have compiled a package for your own distribution, just send me the link or make a pull request.
