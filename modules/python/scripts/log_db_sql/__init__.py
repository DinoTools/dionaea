#################################################################################
#                                Dionaea
#                            - catches bugs -
#
#  Copyright (c) 2016 PhiBo
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
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#
################################################################################
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
