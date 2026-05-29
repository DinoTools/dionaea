# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
#
# SPDX-License-Identifier: GPL-2.0-or-later

from dionaea import IHandlerLoader
from dionaea.core import ihandler, g_dionaea
from dionaea.exception import LoaderError

import logging
import datetime

logger = logging.getLogger('fail2ban')
logger.setLevel(logging.DEBUG)


class Fail2BanHandlerLoader(IHandlerLoader):
    name = "fail2ban"

    @classmethod
    def start(cls, config=None):
        try:
            return fail2banhandler(config=config)
        except LoaderError as e:
            logger.error(e.msg, *e.args)
        return None


class fail2banhandler(ihandler):
    def __init__(self, config=None):
        logger.debug("%s ready!" % (self.__class__.__name__))
        ihandler.__init__(self, "*")
        if config is None:
            config = {}
        offers = config.get("offers", "var/dionaea/offers.f2b")
        downloads = config.get("downloads", "var/dionaea/downloads.f2b")
        try:
            self.offers = open(offers, "a")
        except OSError as e:
            raise LoaderError("Unable to open file %s Error message '%s'", offers, e.strerror)
        try:
            self.downloads = open(downloads, "a")
        except OSError as e:
            raise LoaderError("Unable to open file %s Error message '%s'", downloads, e.strerror)

    def handle_incident_dionaea_download_offer(self, icd):
        data = "%s %s %s %s\n" % (datetime.datetime.now().isoformat(
        ), icd.con.local.host, icd.con.remote.host, icd.url)
        self.offers.write(data)
        self.offers.flush()

    def handle_incident_dionaea_download_complete_hash(self, icd):
        data = "%s %s %s %s %s\n" % (datetime.datetime.now().isoformat(
        ), icd.con.local.host, icd.con.remote.host, icd.url, icd.md5hash)
        self.downloads.write(data)
        self.downloads.flush()
