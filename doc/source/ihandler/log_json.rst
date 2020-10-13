..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2016 PhiBo (DinoTools)

    SPDX-License-Identifier: GPL-2.0-or-later

log_json
========

This ihandler can submit information about attacks/connections encoded as json.

.. warning:: This ihandler is in pre alpha state and it might be changed or removed in the near future.

Configure
---------


flat_data

    Set to true to flatten object lists.

handlers

    List of URLs to submit the information to.
    At the moment only file, http and https are supported.

Format
------

Format of the connection information:

.. code-block:: JavaScript

    {
        "connection": {
            "local": {
                "address": "<string:local ip address>",
                "port": <integer:local port>,
            },
            "protocol": "<string:service name e.g. httpd>",
            "remote": {
                "address": "<string:remote ip address>",
                "port": <integer:remote port>,
                "hostname": "<string:hostname of the remote host>"
            },
            "transport": "<string:transport protocol e.g. tcp or udp>",
            "type": "<string:connection type e.g. accepted, listen, ...>"
        }
    }


Example config
--------------

.. literalinclude:: ../../../conf/ihandlers/log_json.yaml.in
   :language: yaml
   :caption: ihandlers/log_json.yaml
