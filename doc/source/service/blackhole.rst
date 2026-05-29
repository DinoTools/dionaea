..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2016 PhiBo (DinoTools)

    SPDX-License-Identifier: GPL-2.0-or-later

Black hole
==========

The black hole module can be used to bind a service to a port.
The service does not respond to any submitted data.
But the bistreams can be used to create new modules.

Example config
--------------

.. literalinclude:: ../../../conf/services/blackhole.yaml
    :language: yaml
    :caption: services/blackhole.yaml
