..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2011-2012 Markus Koetter
    SPDX-FileCopyrightText: 2015-2017 PhiBo (DinoTools)

    SPDX-License-Identifier: GPL-2.0-or-later

Filter
======

Only continue with the processing pipeline if all conditions match.

Configuration
-------------

**protocols**

    Comma separated list of connection types.

**types**

    Comma separated list of connection types.

    - accept - dionaea accepts a new connection from a remote host
    - connect - dionaea makes a connection to a remote host
