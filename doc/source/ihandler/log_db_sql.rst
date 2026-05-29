..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2016 PhiBo (DinoTools)

    SPDX-License-Identifier: GPL-2.0-or-later

log_db_sql
==========

.. warning:: This ihanlder is experimental.

This incident handler can write interesting information about attacks and connections into an SQL database.
It uses `SQLAlchemy`_ to support different databases.

Example config
--------------

.. literalinclude:: ../../../conf/ihandlers/log_db_sql.yaml.in
   :language: yaml
   :caption: ihandlers/log_db_sql.yaml

.. _SQLAlchemy: http://www.sqlalchemy.org/
