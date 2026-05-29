..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2016 PhiBo (DinoTools)

    SPDX-License-Identifier: GPL-2.0-or-later

log_incident
============

This ihandler can be used to export incidents in realtime to be processed by external programs.

.. warning:: This ihandler is in pre alpha state and it might be changed or removed in the future.

Configure
---------

handlers

    List of URLs to submit the information to.
    At the moment only file, http and https are supported.

Format
------

.. code-block:: JavaScript

   {
      "name": "<sensor-name>",
      "origin": "<name of the incident>",
      "timestamp": "<date in ISO 8601>",
      "data": {
         "connection": {
            "id": <internal ID>,
            "local_ip": "<local IP>",
            "local_port": <local port>,
            "remote_ip": "<remote IP>",
            "remote_hostname": "<remote hostname if resolvable>",
            "remote_port": <remote port>,
            "protocol": "<protocol>",
            "transport": "<transport tcp|udp>"
         }
      }
   }

Example config
--------------

.. literalinclude:: ../../../conf/ihandlers/log_incident.yaml.in
   :language: yaml
   :caption: ihandlers/log_incident.yaml
