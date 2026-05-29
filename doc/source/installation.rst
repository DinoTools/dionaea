..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2011-2012 Markus Koetter
    SPDX-FileCopyrightText: 2015-2017 PhiBo (DinoTools)

    SPDX-License-Identifier: GPL-2.0-or-later

Installation
============

Requirements
------------

For best performance and functionality we have documented some recommendations for running dionaea.

+------------------+--------------------------------------------------------------+
| Platform         | Options                                                      |
+==================+==============================================================+
| Operating System | - **Ubuntu 18.04 LTS** (recommended) (used for development)  |
|                  | - **Debian 10** (recommended)                                |
+------------------+--------------------------------------------------------------+
| Python Runtime   | - **3.9** (*recommended*)                                    |
|                  | - **3.8** (*recommended*)                                    |
|                  | - 3.7                                                        |
|                  | - 3.6                                                        |
+------------------+--------------------------------------------------------------+

At the moment we do not recommend using Ubtuntu 20.04 or Debian 11 because libemu has been dropped from the package repository. Feel free to have a look at `Future of shellcode emulation (libemu)?`_ for more information and to help use.

Basic stuff
-----------

.. _Download the source code:

Download the source code
^^^^^^^^^^^^^^^^^^^^^^^^

You can download the source code from the `release page`_ or by using the git command.

.. code-block:: console

    git clone https://github.com/DinoTools/dionaea.git
    cd dionaea


.. _release page: https://github.com/DinoTools/dionaea/releases

Docker
------

We provide an official docker image. For detailed instructions please have a look at the `dinotools/dionaea docker hub`_ page

Ubuntu 18.04
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
        python3-boto3 \
        fonts-liberation

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

.. note:: Before you use 3rd party packages please check if you get the latest version of dionaea.

.. note:: We are not responsible and it is hard to debug if you use 3rd party packages. If you have any issues with the packages please also contact the package maintainer.

.. _dinotools/dionaea docker hub: https://hub.docker.com/r/dinotools/dionaea
.. _Future of shellcode emulation (libemu)?: https://github.com/DinoTools/dionaea/issues/306
