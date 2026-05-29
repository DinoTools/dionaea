..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2011-2012 Markus Koetter
    SPDX-FileCopyrightText: 2015-2017 PhiBo (DinoTools)

    SPDX-License-Identifier: GPL-2.0-or-later

Streamdumper
============

This processor can dump a connection as bi-directional stream.
The dump can be used to replay an attack on ip-level without messing with pcap and tcpreplay.

Configuration
-------------

**path**

    Dumps will be created in this directory.
