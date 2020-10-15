..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2011-2012 Markus Koetter
    SPDX-FileCopyrightText: 2015-2017 PhiBo (DinoTools)

    SPDX-License-Identifier: GPL-2.0-or-later

Modules
=======

The subsections name is the name of the module dionaea will try to load,
most modules got rather simplistic names, the pcap module will use
libpcap, the curl module libcurl, the emu module libemu ...
The python module is special, as the python module can load python
scripts, which offer services, and each services can have its own options.

List of available modules

.. toctree::
    :maxdepth: 2

    curl
    emu
    pcap
    python
