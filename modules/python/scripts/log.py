###############################################################################
#                                Dionaea
#                            - catches bugs -
# 
# 
# 
#  Copyright (C) 2009  Paul Baecher & Markus Koetter
# 
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
# 
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
# 
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
# 
# 
#              contact nepenthesdev@gmail.com
# 
###############################################################################

from dionaea.core import dlhfn
import logging

global handler
global logger


class DionaeaLogHandler(logging.Handler):
    def __init__(self):
        logging.Handler.__init__(self, logging.DEBUG)

    def emit(self, record):
        dlhfn(record.name, record.levelno, record.pathname, record.lineno, record.msg)


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
    global logger
    global handler
    logger.removeHandler(handler)
