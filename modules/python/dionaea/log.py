# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
#
# SPDX-License-Identifier: GPL-2.0-or-later

from dionaea.core import dlhfn
import logging

handler = None
logger = None


class DionaeaLogHandler(logging.Handler):
    def __init__(self):
        logging.Handler.__init__(self, logging.DEBUG)

    def emit(self, record):
        msg = self.format(record)
        dlhfn(record.name, record.levelno, record.pathname, record.lineno, msg)


def new():
    global logger
    global handler
    logger = logging.getLogger('')
    logger.setLevel(logging.DEBUG)
    handler = DionaeaLogHandler()
    logger.addHandler(handler)


def start():
    pass


def stop():
    logger.removeHandler(handler)
