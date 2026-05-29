..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2011-2012 Markus Koetter
    SPDX-FileCopyrightText: 2015-2017 PhiBo (DinoTools)

    SPDX-License-Identifier: GPL-2.0-or-later

MySQL
=====

This module implements the MySQL wire stream protocol - backed up by
sqlite as database. Please refer to 2011-05-15 Extending Dionaea
<http://carnivore.it/2011/05/15/extending_dionaea> for more information.

Example config
--------------

.. literalinclude:: ../../../conf/services/mysql.yaml
    :language: yaml
    :caption: services/mysql.yaml
