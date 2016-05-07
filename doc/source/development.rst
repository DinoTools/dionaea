Development
===========

Vagrant
-------

Vagrant can be used to setup a development environment for dionaea within minutes.


Install
^^^^^^^

First install `Vagrant`_ and `VirtualBox`_.

If everything has been setup correctly clone the git repository and use vagrant to bootstrap and start the environment.

.. code-block:: console

    $ git clone https://github.com/DinoTools/dionaea.git
    $ cd dionaea/vagrant
    $ vagrant up


All files will be installed in the :code:`/opt/dionaea` directory.


Run
^^^

Access the development environment, edit the config files and start dionaea with the following command.

.. code-block:: console

    $ sudo /opt/dionaea/bin/dionaea -c /opt/dionaea/etc/dionaea/dionaea.cfg -l all,-debug -L '*'

Rebuild and test
^^^^^^^^^^^^^^^^

To rebuild and install dionaea run the flowing commands.

.. code-block:: console

    $ cd /vagrant
    $ make
    $ sudo make install

See `Run`_ for more information on how to start dionaea.


Ubuntu 14.04
------------

Instead of using Vagrant you can use a Ubuntu 14.04 system to setup your development environment.
In this section we will use the scripts used to setup the Vagrant environment to bootstrap a fresh Ubuntu system.
If you like you can follow the :doc:`installation` 'From Source' guide to setup everything by hand.

Install
^^^^^^^

First install `Ubuntu`_.

If everything has been setup correctly clone the git repository and run the bootstrap script.

.. code-block:: console

    $ git clone https://github.com/DinoTools/dionaea.git
    $ vagrant
    $ ./bootstrap.sh

All files will be installed in the :code:`/opt/dionaea` directory.

Rebuild and test
^^^^^^^^^^^^^^^^

Rebuild, install and start dionaea from the root of the git repository.

.. code-block:: console

    $ make
    $ sudo make install
    $ sudo /opt/dionaea/bin/dionaea -c /opt/dionaea/etc/dionaea/dionaea.cfg -l all,-debug -L '*'


This can also be done in one line.

.. code-block:: console

    $ make && sudo make install && sudo dionaea -c /opt/dionaea/etc/dionaea/dionaea.cfg -l all,-debug -L '*'

.. _Vagrant: https://www.vagrantup.com/
.. _VirtualBox: https://www.virtualbox.org/
.. _Ubuntu: https://ubuntu.com/
