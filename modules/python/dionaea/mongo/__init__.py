# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2017 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

from dionaea import ServiceLoader
from .mongo import mongod


class MongoService(ServiceLoader):
    name = "mongo"

    @classmethod
    def start(cls, addr,  iface=None, config=None):
        daemon = mongod()
        daemon.apply_config(config)
        daemon.bind(addr, 27017, iface=iface)
        daemon.listen()
        return daemon
