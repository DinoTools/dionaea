# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2009  Paul Baecher & Markus Koetter
#
# SPDX-License-Identifier: GPL-2.0-or-later

from dionaea import IHandlerLoader
from dionaea.core import ihandler, incident, g_dionaea
from dionaea.exception import LoaderError
from dionaea.util import md5file

import os
import logging
logger = logging.getLogger('store')
logger.setLevel(logging.DEBUG)


class StoreHandlerLoader(IHandlerLoader):
    name = "store"

    @classmethod
    def start(cls, config=None):
        try:
            return storehandler("dionaea.download.complete", config=config)
        except LoaderError as e:
            logger.error(e.msg, *e.args)
            return None


class storehandler(ihandler):
    def __init__(self, path, config=None):
        logger.debug("%s ready!" % (self.__class__.__name__))
        ihandler.__init__(self, path)

        dionaea_config = g_dionaea.config().get("dionaea")
        self.download_dir = dionaea_config.get("download.dir")
        if self.download_dir is None:
            raise LoaderError("Setting download.dir not configured")
        else:
            if not os.path.isdir(self.download_dir):
                raise LoaderError("'%s' is not a directory", self.download_dir)
            if not os.access(self.download_dir, os.W_OK):
                raise LoaderError("Not allowed to create files in the '%s' directory", self.download_dir)

    def handle_incident(self, icd):
        logger.debug("storing file")
        p = icd.path
        # ToDo: use sha1 or sha256
        md5 = md5file(p)
        # ToDo: use sys.path.join()
        n = os.path.join(self.download_dir, md5)
        i = incident("dionaea.download.complete.hash")
        i.file = n
        i.url = icd.url
        if hasattr(icd, 'con'):
            i.con = icd.con
        i.md5hash = md5
        i.report()

        try:
            os.stat(n)
            i = incident("dionaea.download.complete.again")
            logger.debug("file %s already existed" % md5)
        except OSError:
            logger.debug("saving new file %s to %s" % (md5, n))
            os.link(p, n)
            i = incident("dionaea.download.complete.unique")
        i.file = n
        if hasattr(icd, 'con'):
            i.con = icd.con
        i.url = icd.url
        i.md5hash = md5
        i.report()
