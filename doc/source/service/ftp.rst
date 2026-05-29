..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2011-2012 Markus Koetter
    SPDX-FileCopyrightText: 2015-2017 PhiBo (DinoTools)

    SPDX-License-Identifier: GPL-2.0-or-later

FTP
===

Dionaea provives a basic ftp server on port 21, it can create
directories and upload and download files. From my own experience there
are very little automated attacks on ftp services and I'm yet to see
something interesting happening on port 21.

Example config
--------------

.. literalinclude:: ../../../conf/services/ftp.yaml.in
    :language: yaml
    :caption: services/ftp.yaml
