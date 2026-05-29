..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2011-2012 Markus Koetter
    SPDX-FileCopyrightText: 2015-2017 PhiBo (DinoTools)

    SPDX-License-Identifier: GPL-2.0-or-later

TFTP
====

Written to test the udp connection code, dionaea provides a tftp server
on port 69, which can serve files. Even though there were
vulnerabilities in tftp services, I'm yet to see an automated attack on
tftp services.

Example config
--------------

.. literalinclude:: ../../../conf/services/tftp.yaml.in
    :language: yaml
    :caption: services/tftp.yaml
