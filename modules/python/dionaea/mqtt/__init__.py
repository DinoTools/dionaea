# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2015 Tan Kean Siong
# SPDX-FileCopyrightText: 2016 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

from dionaea import ServiceLoader
from .mqtt import mqttd


class MQTTService(ServiceLoader):
    name = "mqtt"

    @classmethod
    def start(cls, addr,  iface=None, config=None):
        daemon = mqttd()
        daemon.bind(addr, 1883, iface=iface)
        daemon.apply_config(config)
        daemon.listen()
        return daemon
