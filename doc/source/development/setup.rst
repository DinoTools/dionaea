Development
===========

Docker
------

The `docker-compose`_ can be used to setup a development envirnment for dionaea.

.. code-block:: console

    $ git clone https://github.com/DinoTools/dionaea.git
    $ cd dionaea/dev/docker
    $ docker-compose up

To debug dionaea it can be started with :code:`gdbserver` and `gdbgui`_.

.. code-block:: console

    $ git clone https://github.com/DinoTools/dionaea.git
    $ cd dionaea/dev/docker
    $ docker-compose -f docker-compose.yml -f extra_conf/gdbserver.yml up

The gdbgui frontend is available on the host system http://localhost:5000/.
To connect to the :code:`gdbserver` just select 'Connect to gdbserver' and enter :code:`dionaea:9999` on the frontend.

All source files are monitored with :code:`inotifywait` and if a source file changes dionaea is automatically rebuild and restarted.

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
If you like you can follow the :doc:`../installation` 'From Source' guide to setup everything by hand.

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


Find memory leaks
-----------------

To enable AddressSanitizer you have to add the following parameters to the :code:`configure` script and rebuild dionaea.

.. code-block:: console

    --disable-shared CFLAGS="-fsanitize=address -ggdb" CXXFLAGS="-fsanitize=address -ggdb"

When running dionaea it will print information about overfow errors.
If you would like to stop execution you have to export an additional environment variable.

.. code-block:: console

    export ASAN_OPTIONS='abort_on_error=1'

To get a stacktrace you can use :code:`gdb` and add an additional breakpoint :code:`break __asan_report_error`.

It is also possible to use `asan_symbolize.py python2 script`_ to extract additional information.

.. code-block:: console

    /opt/dionaea/bin/dionaea -c /opt/dionaea/etc/dionaea/dionaea.cfg  2>&1 | python asan_symbolize.py

.. _Vagrant: https://www.vagrantup.com/
.. _VirtualBox: https://www.virtualbox.org/
.. _Ubuntu: https://ubuntu.com/
.. _asan_symbolize.py python2 script: https://llvm.org/svn/llvm-project/compiler-rt/trunk/lib/asan/scripts/asan_symbolize.py
.. _docker-compose: https://docs.docker.com/compose/
.. _gdbgui: https://github.com/cs01/gdbgui/
