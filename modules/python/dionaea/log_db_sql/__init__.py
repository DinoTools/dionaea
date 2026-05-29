# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2016 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging

from dionaea import IHandlerLoader

logger = logging.getLogger('log_db_sql')
logger.setLevel(logging.DEBUG)


class LogSQLHandlerLoader(IHandlerLoader):
    name = "log_db_sql"

    @classmethod
    def start(cls, config=None):
        from .controller import LogSQLHandler
        return LogSQLHandler("*", config=config)
