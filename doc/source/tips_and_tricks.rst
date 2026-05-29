..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2011-2012 Markus Koetter
    SPDX-FileCopyrightText: 2015-2017 PhiBo (DinoTools)

    SPDX-License-Identifier: GPL-2.0-or-later

Tips and Tricks
===============

.. warning:: The documentation is work in progress.


Rotate bistream files
---------------------

Dionaea does not have and may never will have a function/option to rotate the bistream files.
But you can do this by using a cron job and a simple shell script.

Feel free to use and modify the script below.

.. code-block:: bash

    #!/bin/bash

    # Compress bistream files older than 2 days
    find /opt/dionaea/var/dionaea/bistreams/* -type f -mtime +2 -exec gzip {} \;

    # Clear bistream logs from dionaea every week
    find /opt/dionaea/var/dionaea/bistreams/* -type f -mtime +7 -exec rm {} \;
    find /opt/dionaea/var/dionaea/bistreams/* -type d -empty -delete
