# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2011 Markus Koetter
# SPDX-FileCopyrightText: 2016 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

from dionaea import ServiceLoader
from .mysql import mysqld


class MYSQLService(ServiceLoader):
    name = "mysql"

    @classmethod
    def start(cls, addr,  iface=None, config=None):
        daemon = mysqld()
        daemon.apply_config(config)
        daemon.bind(addr, 3306, iface=iface)
        daemon.listen()
        return daemon
