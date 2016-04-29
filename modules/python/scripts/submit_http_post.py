#*************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (C) 2009  Paul Baecher & Markus Koetter
#*
#* This program is free software; you can redistribute it and/or
#* modify it under the terms of the GNU General Public License
#* as published by the Free Software Foundation; either version 2
#* of the License, or (at your option) any later version.
#*
#* This program is distributed in the hope that it will be useful,
#* but WITHOUT ANY WARRANTY; without even the implied warranty of
#* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#* GNU General Public License for more details.
#*
#* You should have received a copy of the GNU General Public License
#* along with this program; if not, write to the Free Software
#* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#*
#*
#*             contact nepenthesdev@gmail.com
#*
#*******************************************************************************/

from dionaea import IHandlerLoader
from dionaea.core import ihandler, incident, g_dionaea
from dionaea.core import connection
import logging
import json
global p

logger = logging.getLogger('test')
logger.setLevel(logging.DEBUG)


class SubmitHTTPPostLoader(IHandlerLoader):
    name = "submit_http_post"

    @classmethod
    def start(cls, config=None):
        return uniquedownloadihandler("dionaea.download.complete.unique", config=config)


class SubmitHTTPPost(ihandler):
    def __init__(self, path, config=None):
        logger.debug("%s ready!" % (self.__class__.__name__))
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
                for k, v in to.get("field_values", {}):
                    i.set(k, v)

                file_fieldname = to.get("file_fieldname")
                if file_fieldname is not None:
                    i.set("file://%s" % file_fieldname, icd.file)

                i.report()
