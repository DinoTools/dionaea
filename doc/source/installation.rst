Installation
============

At the time of writing the best choice to install dionaea on a server is to use `Ubuntu 16.04`_,
but below you can find how to install it (from source) on other distributions/operating systems.

Basic stuff
-----------

.. _Download the source code:

Download the source code
^^^^^^^^^^^^^^^^^^^^^^^^

You can download the source code from the `release page`_ or by using the git command.

.. code-block:: console

    git clone https://github.com/DinoTools/dionaea.git
    cd  dionaea


.. _release page: https://github.com/DinoTools/dionaea/releases

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

Ubuntu 16.04
------------

From Source
^^^^^^^^^^^

Before you start `download the source code`_ of dionaea.

Install required build dependencies before configuring and building dionaea. ('ttf-liberation' required to 'util/gnuplotsql.py')

.. code-block:: console

    sudo apt-get install \
        build-essential \
        cmake \
        check \
        cython3 \
        libcurl4-openssl-dev \
        libemu-dev \
        libev-dev \
        libglib2.0-dev \
        libloudmouth1-dev \
        libnetfilter-queue-dev \
        libnl-3-dev \
        libpcap-dev \
        libssl-dev \
        libtool \
        libudns-dev \
        python3 \
        python3-dev \
        python3-bson \
        python3-yaml \
        ttf-liberation

After all dependencies have been installed successfully create a build directory and run :code:`cmake` to setup the build process.

.. code-block:: console

    mkdir build
    cd build
    cmake -DCMAKE_INSTALL_PREFIX:PATH=/opt/dionaea ..

Now you should be able to run :code:`make` to build and run :code:`make install` to install the honeypot.

.. code-block:: console

    make
    sudo make install

The new honeypot can be found in the directory :code:`/opt/dionaea`.

.. _Ubuntu 14.04:

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

Before you start `download the source code`_ of dionaea.

Install required build dependencies before configuring and building dionaea.

.. code-block:: console

    $ sudo apt-get install \
        build-essential \
        check \
        cmake3 \
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
        python3-bson \
        python3-yaml

After all dependencies have been installed successfully create a build directory and run :code:`cmake` to setup the build process.

.. code-block:: console

    mkdir build
    cd build
    cmake -DCMAKE_INSTALL_PREFIX:PATH=/opt/dionaea ..

Now you should be able to run :code:`make` to build and run :code:`make install` to install the honeypot.

.. code-block:: console

    make
    sudo make install

The new honeypot can be found in the directory :code:`/opt/dionaea`.

3rd-party packages
------------------

The packages below are 3rd party provided, which is appreciated.
If you have compiled a package for your own distribution, just send me the link or make a pull request.
