#################################################################################
#                                Dionaea
#                            - catches bugs -
#
#  Copyright (c) 2016 PhiBo (DinoTools)
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
################################################################################

from datetime import datetime
import json
import logging
from urllib.parse import urlparse

from dionaea import IHandlerLoader
from dionaea.core import ihandler, connection
from dionaea.exception import LoaderError


logger = logging.getLogger("log_incident")
logger.setLevel(logging.DEBUG)


class FileHandler(object):
    handle_schemes = ["file"]

    def __init__(self, url):
        self.url = url
        url = urlparse(url)
        try:
            self.fp = open(url.path, "a")
        except OSError as e:
            raise LoaderError("Unable to open file %s Error message '%s'", url.path, e.strerror)

    def submit(self, data):
        data = json.dumps(data)
        self.fp.write(data)
        self.fp.write("\n")
        self.fp.flush()


class HTTPHandler(object):
    handle_schemes = ["http", "https"]

    def __init__(self, url):
        self.url = url

    def submit(self, data):
        from urllib.request import Request, urlopen
        data = json.dumps(data)
        data = data.encode("ASCII")
        req = Request(
            self.url,
            data=data,
            headers={
                "Content-Type": "application/json"
            }
        )
        # ToDo: parse response
        response = urlopen(req)


class LogJsonHandlerLoader(IHandlerLoader):
    name = "log_incident"

    @classmethod
    def start(cls, config=None):
        try:
            return LogJsonHandler("*", config=config)
        except LoaderError as e:
            logger.error(e.msg, *e.args)


class LogJsonHandler(ihandler):
    def __init__(self, path, config=None):
        logger.debug("%s ready!", self.__class__.__name__)
        ihandler.__init__(self, path)
        self.path = path
        self._config = config

        self.handlers = []
        handlers = config.get("handlers")
        if not isinstance(handlers, list) or len(handlers) == 0:
            logger.warning("No handlers specified")
            # Set empty list on error
            handlers = []

        for handler in handlers:
            url = urlparse(handler)
            for h in (FileHandler, HTTPHandler,):
                if url.scheme in h.handle_schemes:
                    self.handlers.append(h(url=handler))
                    break

    def handle_incident(self, icd):
        icd.dump()

        idata = {}
        for k in icd.keys():
            n = k.decode("ASCII")
            v = getattr(icd, n)
            if isinstance(v, (int, float, str, list, tuple, dict)) or v is None:
                logger.debug("Add '%s' to icd data", n)
                idata[n] = v
            elif isinstance(v, set):
                # a set() is not JSON serializable, so we use lists instead
                logger.debug("Add '%s' to icd data", n)
                idata[n] = list(v)
            elif isinstance(v, bytes):
                logger.debug("Decode and add '%s' to icd data", n)
                idata[n] = v.decode(encoding="utf-8", errors="replace")
            elif isinstance(v, connection):
                k = k.decode("ASCII")
                if k == "con":
                    k = "connection"
                idata[k] = {
                    "id": id(v),
                    "protocol": v.protocol,
                    "transport": v.transport,
                    #"type": v.connection_type,
                    "local_ip": v.local.host,
                    "local_port": v.local.port,
                    "remote_hostname": v.remote.hostname,
                    "remote_ip": v.remote.host,
                    "remote_port": v.remote.port
                }
            else:
                logger.warning("Incident '%s' with unknown data type '%s' for key '%s'", icd.origin, type(v), k)

        data = {
            "timestamp": datetime.utcnow().isoformat(),
            "name": "dionaea",
            "origin": icd.origin,
            "data": idata
        }

        for handler in self.handlers:
            handler.submit(data)
