Development
===========

Vagrant
-------

Vagrant can be used to setup a development environment for dionaea within minutes.


Install
^^^^^^^

First install `Vagrant`_ and `VirtualBox`_.

If everything has been setup correctly clone the git repository and use vagrant to start the environment.

.. code-block:: console

    $ git clone https://github.com/dionaea-honeypot/dionaea.git
    $ cd dionaea/vagrant
    $ vagrant up


Run the following command to access the development environment.

.. code-block:: console

    $ vagrant ssh


Rebuild and test
^^^^^^^^^^^^^^^^

By default the dionaea service is started in the virtual machine.
Stop the service before rebuilding and testing your changes.

.. code-block:: console

    $ sudo service dionaea stop


Now rebuild, install and start dionaea.

.. code-block:: console

    $ cd /vagrant
    $ make
    $ sudo make install
    $ sudo dionaea -c /etc/dionaea/dionaea.conf -l all,-debug -L '*'


This can also be done in one line.

.. code-block:: console

    $ cd /vagrant
    $ make && sudo make install && sudo dionaea -c /etc/dionaea/dionaea.conf -l all,-debug -L '*'


.. _Vagrant: https://www.vagrantup.com/
.. _VirtualBox: https://www.virtualbox.org/
