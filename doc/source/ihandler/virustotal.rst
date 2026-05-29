..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2011-2012 Markus Koetter
    SPDX-FileCopyrightText: 2015-2017 PhiBo (DinoTools)

    SPDX-License-Identifier: GPL-2.0-or-later

VirusTotal
==========

This ihandler submits the captured malware samples to the `VirusTotal`_ service for further analysis.

Configuration
-------------

**apikey**

    The VirusTotal API-Key.

**file**

    SQLite database file used to cache the results.


Example config
--------------

.. literalinclude:: ../../../conf/ihandlers/virustotal.yaml.in
   :language: yaml
   :caption: ihandlers/virustotal.yaml

.. _VirusTotal: https://virustotal.com/
