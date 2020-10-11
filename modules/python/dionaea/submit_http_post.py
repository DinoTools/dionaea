# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging

from dionaea import IHandlerLoader
from dionaea.core import ihandler, incident

logger = logging.getLogger('submit_http_post')
logger.setLevel(logging.DEBUG)


class SubmitHTTPPostLoader(IHandlerLoader):
    name = "submit_http_post"

    @classmethod
    def start(cls, config=None):
        return SubmitHTTPPost("dionaea.download.complete.unique", config=config)


class SubmitHTTPPost(ihandler):
    def __init__(self, path, config=None):
        logger.debug("%s ready!", self.__class__.__name__)
        ihandler.__init__(self, path)
        self.tos = config.get("submit", [])

    def handle_incident(self, icd):
        logger.debug("submitting file")

        for name, to in self.tos.items():
            urls = to.get("urls")
            if urls is None or len(urls) == 0:
                logger.warn("your configuration lacks urls to submit to %s", name)
                continue

            for url in urls:
                i = incident("dionaea.upload.request")
                i._url = url

                # copy all values for this url
                field_values = to.get("field_values")
                if field_values is None:
                    field_values = {}
                for k, v in field_values.items():
                    i.set(k, v)

                file_fieldname = to.get("file_fieldname")
                if file_fieldname is not None:
                    i.set("file://%s" % file_fieldname, icd.file)

                i.report()
